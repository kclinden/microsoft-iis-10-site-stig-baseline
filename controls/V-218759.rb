# encoding: UTF-8

control 'V-218759' do
  title 'Directory Browsing on the IIS 10.0 website must be disabled.'
  desc  "Directory browsing allows the contents of a directory to be displayed
upon request from a web client. If directory browsing is enabled for a
directory in IIS, users could receive a web page listing the contents of the
directory. If directory browsing is enabled the risk of inadvertently
disclosing sensitive content is increased."
  desc  'rationale', ''
  desc  'check', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Click the Site.

    Double-click the \"Directory Browsing\" icon.

    If \"Directory Browsing\" is not installed, this is Not Applicable.

    Under the \"Actions\" pane, verify \"Directory Browsing\" is \"Disabled\".

    If \"Directory Browsing\" is not \"Disabled\", this is a finding.
  "
  desc  'fix', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.

    Click the Site.

    Double-click the \"Directory Browsing\" icon.

    Under the \"Actions\" pane, click \"Disabled\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag gid: 'V-218759'
  tag rid: 'SV-218759r558649_rule'
  tag stig_id: 'IIST-SI-000231'
  tag fix_id: 'F-20230r311176_fix'
  tag cci: ['SV-109343', 'V-100239', 'CCI-001310']
  tag nist: ['SI-10']
end

