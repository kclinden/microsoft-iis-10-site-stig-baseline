# encoding: UTF-8

control 'V-218760' do
  title "Warning and error messages displayed to clients must be modified to
minimize the identity of the IIS 10.0 website, patches, loaded modules, and
directory paths."
  desc  "HTTP error pages contain information that could enable an attacker to
gain access to an information system. Failure to prevent the sending of HTTP
error pages with full information to remote requesters exposes internal
configuration information to potential attackers."
  desc  'rationale', ''
  desc  'check', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.

    Click the site name under review.

    Double-click the \"Error Pages\" icon.

    Click each error message and click \"Edit Feature\" setting from the
\"Actions\" pane.

    If any error message is not set to \"Detailed errors for local requests and
custom error pages for remote requests\", this is a finding.
  "
  desc  'fix', "
    Follow the procedures below for each site hosted on the IIS 10.0 web server:

    Open the IIS 10.0 Manager.

    Click the site name under review.

    Double-click the \"Error Pages\" icon.

    Click each error message and click \"Edit Feature\" Setting from the
\"Actions\" pane; set each error message to \"Detailed errors for local
requests and custom error pages for remote requests\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag gid: 'V-218760'
  tag rid: 'SV-218760r558649_rule'
  tag stig_id: 'IIST-SI-000233'
  tag fix_id: 'F-20231r311179_fix'
  tag cci: ['V-100241', 'SV-109345', 'CCI-001312']
  tag nist: ['SI-11 a']

  get_names = command("Get-Website | select name | findstr /v 'name ---'").stdout.strip.split("\r\n")
  get_errorMode = command('Get-WebConfigurationProperty -pspath "IIS:\Sites\*" -Filter system.webServer/httpErrors -Name errorMode').stdout.strip.split("\r\n")

  get_errorMode.zip(get_names).each do |errorMode, names|
    n = names.strip

    describe "The IIS site: #{n} websites error mode" do
      subject { errorMode }
      it { should cmp 'DetailedLocalOnly' }
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

