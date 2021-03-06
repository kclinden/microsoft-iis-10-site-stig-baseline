# encoding: UTF-8

control 'V-218768' do
  title "The IIS 10.0 private website must employ cryptographic mechanisms
(TLS) and require client certificates."
  desc  "When data is written to digital media, such as hard drives, mobile
computers, external/removable hard drives, personal digital assistants,
flash/thumb drives, etc., there is risk of data loss and data compromise. User
identities and passwords stored on the hard drive of the hosting hardware must
be encrypted to protect the data from easily being discovered and used by an
unauthorized user to access the hosted applications. The cryptographic
libraries and functionality used to store and retrieve the user identifiers and
passwords must be part of the web server.


  "
  desc  'rationale', ''
  desc  'check', "
    Note: If SSL is installed on load balancer/proxy server through which
traffic is routed to the IIS 10.0 server, and the IIS 10.0 server receives
traffic from the load balancer/proxy server, the SSL requirement must be met on
the load balancer/proxy server.

    Note: If this is a public facing web server, this requirement is Not
Applicable.

    Note: If this server is hosting WSUS, this requirement is Not Applicable.

    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.
    Double-click the \"SSL Settings\" icon under the \"IIS\" section.
    Verify \"Require SSL\" is checked.
    Verify \"Client Certificates Required\" is selected.
    Click the site under review.
    Select \"Configuration Editor\" under the \"Management\" section.
    From the \"Section:\" drop-down list at the top of the configuration
editor, locate \"system.webServer/security/access\".
    The value for \"sslFlags\" set must include \"ssl128\".

    If the \"Require SSL\" is not selected, this is a finding.
    If the \"Client Certificates Required\" is not selected, this is a finding.
    If the \"sslFlags\" is not set to \"ssl128\", this is a finding.
  "
  desc  'fix', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.

    Double-click the \"SSL Settings\" icon under the \"IIS\" section.

    Select the \"Require SSL\" setting.

    Select the \"Client Certificates Required\" setting.

    Click \"Apply\" in the \"Actions\" pane.

    Click the site under review.

    Select \"Configuration Editor\" under the \"Management\" section.

    From the \"Section:\" drop-down list at the top of the configuration
editor, locate \"system.webServer/security/access\".

    Click on the drop-down list for \"sslFlags\".

    Select the \"Ssl128\" check box.

    Click \"Apply\" in the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000429-WSR-000113'
  tag satisfies: ['SRG-APP-000429-WSR-000113', 'SRG-APP-000439-WSR-000151',
'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182']
  tag gid: 'V-218768'
  tag rid: 'SV-218768r558649_rule'
  tag stig_id: 'IIST-SI-000242'
  tag fix_id: 'F-20239r311203_fix'
  tag cci: ['V-100257', 'SV-109361', 'CCI-002476']
  tag nist: ['SC-28 (1)']

  get_names = json(command: 'ConvertTo-Json @(Get-Website | select -expand name)').params

  get_names.each do |site_name|
    iis_configuration = json(command: "Get-WebConfigurationProperty -Filter system.webServer/security/access 'IIS:\\Sites\\#{site_name}'  -Name * | ConvertTo-Json")

    describe "IIS sessionState for site :'#{site_name}'" do
      subject { iis_configuration }
      its('sslFlags') { should include 'Ssl' }
      its('sslFlags') { should include 'SslRequireCert' }
      its('sslFlags') { should include 'Ssl128' }
    end
  end

  if get_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end

end

