# Running nginx2root-check with Ansible

The checker emits JSON and uses a stable exit-code contract, but Ansible should parse the result rather than relying on the command exit alone.

This example copies the repository to a remote temporary directory, runs the check as root, and always removes the temporary copy.

```yaml
- name: Check nginx2root accounting
  hosts: nginx
  become: true
  tasks:
    - name: Create remote temporary directory
      ansible.builtin.tempfile:
        state: directory
        prefix: nginx2root-check-
      register: nginx2root_tmp

    - name: Run nginx2root check
      block:
        - name: Copy checker
          ansible.builtin.copy:
            src: /path/to/nginx2root-check/
            dest: "{{ nginx2root_tmp.path }}/"
            mode: preserve

        - name: Exercise installed nginx binary
          ansible.builtin.command:
            argv:
              - python3
              - "{{ nginx2root_tmp.path }}/nginx2root-check"
              - --acknowledge-owned-system
              - I-AM-AUTHORIZED
              - --json
          register: nginx2root_command
          changed_when: false
          failed_when: false

        - name: Parse evidence
          ansible.builtin.set_fact:
            nginx2root: "{{ nginx2root_command.stdout | from_json }}"

        - name: Require patched result
          ansible.builtin.assert:
            that:
              - nginx2root.outcome == 'PATCHED'
              - nginx2root.probe.control_bytes | int == 65535
              - nginx2root.probe.production_pids_unchanged | bool
            fail_msg: >-
              {{ inventory_hostname }} is not proven patched:
              {{ nginx2root.outcome }} — {{ nginx2root.reason }}
      always:
        - name: Remove remote temporary directory
          ansible.builtin.file:
            path: "{{ nginx2root_tmp.path }}"
            state: absent
```

Run a known patched and known vulnerable calibration before trusting the first fleet run.

Do not turn a transport failure, missing process, invalid configuration, or unsupported package into a pass.
