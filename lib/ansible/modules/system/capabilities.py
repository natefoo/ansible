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
      - The path to the file to be managed.
    type: str
    required: yes
    aliases: [ key, name, dest ]
  capability:
    description:
      - List of capabilities to set (with operators and flags). If unset, any existing capabilities will be removed. The
        format of this parameter is described in the ``cap_to_text(3)`` man page. Can be either a list, or a string of
        space-separated clauses (as with the arguments to ``setcap(8)``).
    aliases: [ cap ]
  exclusive:
    description
      - Ensure only the capabilities defined in the C(capability) parameter are set (all others are cleared).
notes:
  - The capabilities system will automatically transform operators and flags into the effective set, so for example,
    C(cap_foo=ep) will probably become C(cap_foo+ep).
  - Unlike ``setcap(8)``, this module does not clear capabilities already set unless the C(exclusive) parameter is set.
  - The C(exclusive) option is not compatible with loops: each loop iteration will erase the capabilities set by the
    previous iteration. Instead, pass a list of capabilities directly in the C(capability) parameter.
author:
- Nate Coraor (@natefoo)
'''

EXAMPLES = r'''
- name: Set cap_sys_chroot+ep on /foo
  capabilities:
    path: /foo
    capability: cap_sys_chroot+ep

- name: Set both cap_sys_chroot and cap_net_bind_service on /foo
  capabilities:
    path: /foo
    capability:
      - cap_sys_chroot+ep
      - cap_net_bind_service+ep

- name: Remove cap_net_bind_service from /foo
  capabilities:
    path: /foo
    capability: cap_net_bind_service=

- name: Remove all capabilities from /foo
  capabilities:
    path: /foo

- name: Remove all capabilities from /foo using explicit capability syntax
  capabilities:
    path: /foo
    capability: all=
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import string_types

OPS = ('=', '-', '+')

# Note to maintainers: the man page for setcap(8) is sparse; setcap works in somewhat surprising ways (documented
# throughout the module). The implementation of setcap(8) is not specified in POSIX.1e, so we have tried not to rely too
# much on the current implementation (even though there is currently only one).


class CapabilitiesModule(object):
    platform = 'Linux'
    distribution = None

    def __init__(self, module):
        self.module = module
        self.path = module.params['path'].strip()
        self.capability = module.params['capability']
        self.exclusive = module.params['exclusive']
        self.getcap_cmd = module.get_bin_path('getcap', required=True)
        self.setcap_cmd = module.get_bin_path('setcap', required=True)
        self.__getcap = None

        self._validate_params()
        self.run()

    def __exit(self, method, **kwargs):
        method(path=self.path, **kwargs)

    def exit(self, changed=False, **kwargs):
        """Exit normally.
        """
        self.__exit(self.module.exit_json, changed=changed, **kwargs)

    def fail(self, **kwargs):
        """Exit indicating failure.
        """
        self.__exit(self.module.fail_json, **kwargs)

    def _validate_params(self):
        """Validate the parameters and parameter combinations.

        Clauses in the ``capability`` param take the format described in ``cap_to_text(3)``. This method sets
        ``self.clauses`` to a list of (capability, action-list) tuples.
        """
        if isinstance(self.capability, string_types):
            # capability param is a string as would be arguments passed to setcap(8)
            self.clauses = self._parse_clauses(self.capability.strip().split())
        elif isinstance(self.capability, list):
            # capability param is a list of clauses
            self.clauses = self._parse_clauses(self.capability)
        elif self.capability is None:
            # capability is None, clear all capabilities
            self.exclusive = True
            self.clauses = [('all', '=')]
        else:
            self.fail(msg="Invalid type for 'capability' param: %s" % type(self.capability))

    def _parse_clauses(self, clauses):
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
                caps[-1], actions = self._parse_clause(caps[-1])
                for cap in caps:
                    rval.append((cap, actions))
            else:
                rval.append(self._parse_clause(clause))
        return rval

    def _parse_clause(self, clause):
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
            self.fail(msg="Couldn't find operator (one of: %s)" % str(OPS))
        return (clause[:i], clause[i:])

    def run(self):
        clauses = self.clauses if self.exclusive else self.merge_clauses()
        self.setcap(clauses)

    def merge_clauses(self):
        """Produce a list of clauses for ``setcap(8)`` with current caps merged with desired caps.

        Unlike ``setcap(8)``, which fully replaces a file's capabilities with the set specified on the command (which
        incidentally renders the ``-`` operator useless), we attempt to merge the provided capabilities with the ones
        already set (unless the ``exclusive`` parameter is set).

        :returns: list of (capability, action-list) tuples
        """
        clauses = self.getcap()
        caps = [clause[0] for clause in clauses]
        for clause in self.clauses:
            if clause[0] in caps:
                # If the cap is already set, merge new actions with existing
                i = caps.index(clause[0])
                # We could simply append the value of the capability param to the existing clauses here but
                # ``setcap(8)``'s behavior (which currently does what we want - it takes the last if a cap is duplicated
                # on the command line) is not specified in POSIX.1e and could change in future versions.
                actions = self._merge_actions(clauses[i][1], clause[1])
                clauses[i] = (clause[0], actions)
            else:
                clauses.append(clause)
        return clauses

    def _merge_actions(self, *actions):
        """Merge sets of actions to get the effective set.

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

    def getcap(self, cached=True):
        """Get the capabilities currently set on the file given in the ``path`` param.

        :param cached:  Use cached results if ``True``, otherwise reread capabilities.
        :type cached:   bool
        """
        if self.__getcap is None or not cached:
            cmd = [self.getcap_cmd, '-v', self.path]
            rc, stdout, stderr = self.module.run_command(cmd)
            # If file xattrs are set but no caps are set the output will be:
            #   '/foo ='
            # If file xattrs are unset the output will be:
            #   '/foo'
            # If the file does not eixst the output will be (with rc == 0...):
            #   '/foo (No such file or directory)'
            if rc != 0 or (stdout.strip() != self.path and stdout.count(' =') != 1):
                self.fail(msg="Unable to get capabilities of %s" % self.path, stdout=stdout.strip(), stderr=stderr)
            if stdout.strip() != self.path:
                self.__getcap = self._parse_clauses(stdout.split(' =')[1].strip().split())
        return self.__getcap

    def setcap(self, clauses):
        """Check whether ``setcap(8)`` should run on the given path using ``setcap -v``, and run ``setcap`` if needed.

        NOTE:

        1. setcap -v doesn't check whether the flags in a clause's action list are valid, it just checks for differences
           in the effective set, so the subsequent setcap call can fail.
        2. setcap -v isn't entirely trustworthy: if you try to, for example, ``setcap -v cap_foo+e bar`` on a cap-less
           bar, it will indicate change would occur. If you then ``setcap cap_foo+e bar`` it will appear to succeed, but
           the cap is not set, because a cap cannot be added to the effective set if it's not also in the permitted
           sets. For completeness, we check getcap before and after. However, I don't think it will lie the other way
           and tell you that you don't need to run setcap when in fact you do.

        :param clauses: Clauses as returned by :meth:`_parse_clauses`
        :type clauses: list of tuples
        """
        clauses = ' '.join([''.join(clause) for clause in clauses])
        cmd = [self.setcap_cmd, '-v', clauses, self.path]
        rc, stdout, stderr = self.module.run_command(cmd)
        # rc != 0 means change will occur when running setcap
        if rc != 0 and self.module.check_mode:
            self.exit(changed=True, msg='capabilities changed')
        elif rc != 0:
            self.__setcap(clauses)
        else:
            # No change
            self.exit()

    def __setcap(self, clauses_str):
        """Run ``setcap(8)`` on the given path.

        :param clauses_str: Space-separated clauses (as passed to ``setcap(8)``)
        :type clauses_str:  str
        """
        precaps = self.getcap()
        cmd = [self.setcap_cmd, clauses_str, self.path]
        rc, stdout, stderr = self.module.run_command(cmd)
        if rc != 0:
            self.fail(msg="Unable to set capabilities of %s" % self.path, stdout=stdout, stderr=stderr)
        elif precaps != self.getcap(cached=False):
            self.exit(changed=True, msg='capabilities changed', stdout=stdout)
        else:
            self.exit(stdout=stdout)

# ==============================================================
# main

def main():
    # defining module
    module = AnsibleModule(
        argument_spec=dict(
            path=dict(type='str', required=True, aliases=['key', 'name', 'dest']),
            capability=dict(type='raw', aliases=['cap']),
            exclusive=dict(type='bool', default=False),
        ),
        supports_check_mode=True,
    )

    CapabilitiesModule(module)


if __name__ == '__main__':
    main()
