# encoding: UTF-8

control 'V-218744' do
  title "Mappings to unused and vulnerable scripts on the IIS 10.0 website must
be removed."
  desc  "IIS 10.0 will either allow or deny script execution based on file
extension. The ability to control script execution is controlled through two
features with IIS 10.0, Request Filtering and Handler Mappings.

    For Handler Mappings, the ISSO must document and approve all allowable file
extensions the website allows (white list) and denies (black list). The white
list and black list will be compared to the Handler Mappings in IIS 8. Handler
Mappings at the site level take precedence over Handler Mappings at the server
level.
  "
  desc  'rationale', ''
  desc  'check', "
    For Handler Mappings, the ISSO must document and approve all allowable
scripts the website allows (white list) and denies (black list). The white list
and black list will be compared to the Handler Mappings in IIS 10.0. Handler
Mappings at the site level take precedence over Handler Mappings at the server
level.

    Open the IIS 10.0 Manager.

    Click the site name under review.

    Double-click \"Handler Mappings\".

    If any script file extensions from the black list are enabled, this is a
finding.
  "
  desc  'fix', "
    Open the IIS 10.0 Manager.

    Click the site name under review.

    Double-click \"Handler Mappings\".

    Remove any script file extensions listed on the black list that are enabled.

    Select \"Apply\" from the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag gid: 'V-218744'
  tag rid: 'SV-218744r558649_rule'
  tag stig_id: 'IIST-SI-000215'
  tag fix_id: 'F-20215r311131_fix'
  tag cci: ['V-100209', 'SV-109313', 'CCI-000381']
  tag nist: ['CM-7 a']

  describe 'Manually review the Handler Mappings' do
    skip 'Manually review site Handler Mappings configuration; If any script file
    extensions from the black list are enabled, this is a finding."'
  end

  get_names = json(command: 'ConvertTo-Json @(Get-Website | select -expand name)').params
  if get_names.empty?
    impact 0.0
    desc 'There are no IIS sites configured hence the control is Not-Applicable'

    describe 'No sites where found to be reviewed' do
      skip 'No sites where found to be reviewed'
    end
  end

end

