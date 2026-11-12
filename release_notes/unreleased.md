**Unreleased**

* - **Breaking change:** Convert Cisco Talos Intelligence from BaseConnector to the SOAR SDK. The reputation action summary moves from `action_result.summary.message` to the SDK action message; update playbooks that read the old datapath.
