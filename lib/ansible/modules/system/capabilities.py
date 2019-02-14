#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2014, Nate Coraor <nate@bx.psu.edu>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: capabilities
short_description: Manage Linux capabilities
description:
    - This module manipulates files privileges using the Linux capabilities(7) system.
version_added: "1.6"
options:
    path:
        description:
            - Specifies the path to the file to be managed.
        type: str
        required: yes
        aliases: [ key ]
    capability:
        description:
            - Desired capability to set (with operator and flags, if state is C(present)) or remove (if state is C(absent))
        type: str
        required: yes
        aliases: [ cap ]
    state:
        description:
            - Whether the entry should be present or absent in the file's capabilities.
        type: str
        choices: [ absent, present ]
        default: present
notes:
    - The capabilities system will automatically transform operators and flags into the effective set,
      so for example, C(cap_foo=ep) will probably become C(cap_foo+ep).
    - This module does not attempt to determine the final operator and flags to compare,
      so you will want to ensure that your capabilities argument matches the final capabilities.
author:
- Nate Coraor (@natefoo)
'''

EXAMPLES = r'''
- name: Set cap_sys_chroot+ep on /foo
  capabilities:
    path: /foo
    capability: cap_sys_chroot+ep
    state: present

- name: Remove cap_net_bind_service from /bar
  capabilities:
    path: /bar
    capability: cap_net_bind_service
    state: absent
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import string_types

OPS = ('=', '-', '+')

# The man page for setcap(8) is sparse and it works in somewhat surprising ways
#
# 1. Whatever you specify are the capabilities that the file has after running. Every time you run setcap, it replaces all
#    caps with whatever you specified when you ran it. This means that the '-' operator is effectively useless.
# 2. If a cap appears multiple times in the setcap args, the last one applies.
# 3. setcap -v doesn't check whether the flags are valid, just checks for differences, so the subsequent setcap call can
#    fail
# 4. setcap -v isn't entirely trustworthy: if you try to, for example, `setcap -v cap_foo+e bar` on a cap-less bar, it
#    will indicate change would occur. If you then `setcap cap_foo+e bar` it will appear to succeed, but the cap is not
#    set, because a cap cannot be added to the effective set if it's not also in the permitted sets. So for completeness
#    you actually need to check getcap before and after. That said, I don't think it will lie the other way and tell you
#    that you don't need to setcap when in fact you do.
#
# The above are maybe just an implementation detail you cannot assume about all potential setcap(8) implementations. The
# implementation of setcap is not defined in POSIX.1e.

class CapabilitiesModule(object):
    platform = 'Linux'
    distribution = None

    def __init__(self, module):
        self.module = module
        self.path = module.params['path'].strip()
        self.state = module.params['state']
        self.exclusive = False
        self.getcap_cmd = module.get_bin_path('getcap', required=True)
        self.setcap_cmd = module.get_bin_path('setcap', required=True)

        capability = module.params['capability']
        if isinstance(capability, string_types):
            self._init_clauses(capability.strip().split())
        elif isinstance(capability, list):
            self._init_clauses(capability)
        elif capability is None and self.state == 'absent':
            self.exclusive = True
            self.clauses = [('all', '=')]
        else:
            self.module.fail_json(msg="Invalid type for 'capability' param: %s" % type(capability))

        self.run()

    def _init_clauses(self, clause_strings):
        if self.state == 'absent':
            if self.exclusive:
                # FIXME: english gooder
                self.module.fail_json(msg="The 'exclusive' parameter is nonsensical when 'state = absent'")
            self.clauses = self._parse_clauses(clause_strings, absent=True)
        else:
            self.clauses = self._parse_clauses(clause_strings)

    def run(self):
        if self.exclusive:
            clauses = self.clauses
        else:
            clauses = self.merge_clauses()
        self.setcap(clauses)

    def merge_clauses(self):
        clauses = self.getcap()
        caps = [clause[0] for clause in clauses]
        for clause in self.clauses:
            if clause[0] in caps:
                # If the cap is already set, merge new actions with existing
                i = caps.index(clause[0])
                actions = self._merge_actions(clauses[i][1], clause[1])
                clauses[i] = (clause[0], actions)
            else:
                clauses.append(clause)
        return clauses

    def getcap(self):
        cmd = [self.getcap_cmd, '-v', self.path]
        rc, stdout, stderr = self.module.run_command(cmd)
        # If file xattrs are set but no caps are set the output will be:
        #   '/foo ='
        # If file xattrs are unset the output will be:
        #   '/foo'
        # If the file does not eixst the output will be (with rc == 0...):
        #   '/foo (No such file or directory)'
        if rc != 0 or (stdout.strip() != self.path and stdout.count(' =') != 1):
            self.module.fail_json(msg="Unable to get capabilities of %s" % self.path, stdout=stdout.strip(), stderr=stderr)
        if stdout.strip() != self.path:
            return self._parse_clauses(stdout.split(' =')[1].strip().split())
        return []

    def setcap(self, clauses):
        clauses = ' '.join([''.join(clause) for clause in clauses])
        cmd = [self.setcap_cmd, '-v', clauses, self.path]
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            # Change will occur when running setcap
            if self.module.check_mode:
                self.module.exit_json(changed=True, state=self.state, path=self.path, msg='capabilities changed')
            else:
                self.setcap_real(clauses)
        else:
            self.module.exit_json(changed=False, state=self.state, path=self.path)

    def setcap_real(self, clauses_str):
        cmd = [self.setcap_cmd, clauses_str, self.path]
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.module.fail_json(msg="Unable to set capabilities of %s" % self.path, stdout=stdout, stderr=stderr)
        else:
            # TODO: verify that before == after?
            self.module.exit_json(changed=True, state=self.state, path=self.path, msg='capabilities changed', stdout=stdout)

    def _merge_actions(self, *actions):
        """

        This is done rather than just appending the value of the capability param to the existing clauses because
        ``setcap(8)``'s behavior may be implementation-specific. This allows us to essentially implement what
        ``cap_from_text(3)`` specifies nonexclusively since ``setcap(8)`` doesn't do it, and we can't trust that it will
        always behave the way it does in development on my system.

        :param actions: list of actions to merge, later items supercede
        """
        # FIXME: proper error handling
        flags = set()
        for action in actions:
            mode = None
            eq = False
            l = None
            for c in action:
                if c == '=':
                    assert not eq, "Already had an `=`, can't have 2!"
                    flags.clear()
                    eq = True
                    mode = '+'
                elif c in ('+', '-'):
                    assert l not in ('+', '-'), "Can't do that!"
                    mode = c
                elif c in ('e', 'i', 'p'):
                    assert mode is not None, "No operator!"
                    if mode == '+':
                        flags.add(c)
                    elif mode == '-':
                        flags.discard(c)
                else:
                    raise Exception("Unknown char in action list!: `%s`" % c)
        return '=' + ''.join(sorted(flags))

    def _parse_clauses(self, clauses, absent=False):
        """Parse a list of capabilities clauses

        Clauses take the format described in ``cap_to_text(3)``.

        :param clauses: individual clauses
        :type clauses:  list of str
        
        :returns: list of (capability, action-list) tuples
        """
        rval = []
        for clause in clauses:
            clause = clause.lower()
            # Capabilities with the same action list are condensed into a comma-separated list
            if ',' in clause:
                caps = clause.split(',')
                # The last item in the list has the action list
                caps[-1], actions = self._parse_clause(caps[-1], absent=absent)
                for cap in caps:
                    rval.append((cap, actions))
            else:
                rval.append(self._parse_clause(clause, absent=absent))
        return rval

    def _parse_clause(self, clause, absent=False):
        """Parse a single capabilities clause

        :param clause: capabilities clause with a single capability (no commas)
        :type clause:  str

        :returns: (capability, action-list) tuple
        """
        action = None
        for i, c in enumerate(clause):
            if c in OPS:
                break
        else:
            if absent:
                return (clause, '=')
            self.module.fail_json(msg="Couldn't find operator (one of: %s)" % str(OPS))
        cap = clause[:i]
        if not absent:
            action = clause[i:]
        else:
            # TODO: absent w/ actions is nonsensical, should we fail here instead?
            action = '='
        return (cap, action)


# ==============================================================
# main

def main():
    # defining module
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='str', required=True, aliases=['key']),
            capability=dict(type='raw', aliases=['cap']),
            exclusive=dict(type='bool', default=False),
            state=dict(type='str', default='present', choices=['absent', 'present']),
        ),
        supports_check_mode=True,
    )

    CapabilitiesModule(module)


if __name__ == '__main__':
    main()
