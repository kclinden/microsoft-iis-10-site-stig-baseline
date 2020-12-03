# encoding: UTF-8

control 'V-218749' do
  title "A private IIS 10.0 website authentication mechanism must use client
certificates to transmit session identifier to assure integrity."
  desc  "A DoD private website must use PKI as an authentication mechanism for
web users. Information systems residing behind web servers requiring
authorization based on individual identity must use the identity provided by
certificate-based authentication to support access control decisions. Not using
client certificates allows an attacker unauthenticated access to private
websites.


  "
  desc  'rationale', ''
  desc  'check', "
    Note: If the server being reviewed is a public IIS 10.0 web server, this is
Not Applicable.
    Note: If certificate handling is performed at the Proxy/Load Balancer, this
is not a finding.

    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.

    Double-click the \"SSL Settings\" icon.

    Verify the \"Clients Certificate Required\" check box is selected.

    If the \"Clients Certificate Required\" check box is not selected, this is
a finding.
  "
  desc  'fix', "
    Note: If the server being reviewed is a public IIS 10.0 web server, this is
Not Applicable.
    Note: If certificate handling is performed at the Proxy/Load Balancer, this
is not a finding.

    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.

    Double-click the \"SSL Settings\" icon.

    Verify the \"Clients Certificate Required\" check box is selected.

    Select \"Apply\" from the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000172-WSR-000104'
  tag satisfies: ['SRG-APP-000172-WSR-000104', 'SRG-APP-000224-WSR-000135',
'SRG-APP-000427-WSR-000186']
  tag gid: 'V-218749'
  tag rid: 'SV-218749r558649_rule'
  tag stig_id: 'IIST-SI-000220'
  tag fix_id: 'F-20220r311146_fix'
  tag cci: ['SV-109323', 'V-100219', 'CCI-001188', 'CCI-000197', 'CCI-002470']
  tag nist: ['SC-23 (3)', 'IA-5 (1) (c)', 'SC-23 (5)']
end

