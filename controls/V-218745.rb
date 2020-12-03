# encoding: UTF-8

control 'V-218745' do
  title "The IIS 10.0 website must have resource mappings set to disable the
serving of certain file types."
  desc  "IIS 10.0 will either allow or deny script execution based on file
extension. The ability to control script execution is controlled through two
features with IIS 10.0, Request Filtering and Handler Mappings.

    For Request Filtering, the ISSO must document and approve all allowable
file extensions the website allows (white list) and denies (black list) by the
website. The white list and black list will be compared to the Request
Filtering in IIS 10.0. Request Filtering at the site level take precedence over
Request Filtering at the server level.
  "
  desc  'rationale', ''
  desc  'check', "
    For Request Filtering, the ISSO must document and approve all allowable
scripts the website allows (white list) and denies (black list). The white list
and black list will be compared to the Request Filtering in IIS 10.0. Request
Filtering at the site level take precedence over Request Filtering at the
server level.

    Follow the procedures below for each site hosted on the IIS 10.0 web
server:

    Open the IIS 10.0 Manager.

    Click the site name to review.

    Double-click Request Filtering->File Name Extensions Tab.

    If any script file extensions from the black list are not denied, this is a
finding.
  "
  desc  'fix', "
    Follow the procedures below for each site hosted on the IIS 10.0 web
server:

    Open the IIS 10.0 Manager.

    Click the site name to review.

    Double-click Request Filtering->File Name Extensions Tab->Deny File Name
Extension.

    Add any script file extensions listed on the black list that are not listed.

    Select \"Apply\" from the \"Actions\" pane.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag gid: 'V-218745'
  tag rid: 'SV-218745r558649_rule'
  tag stig_id: 'IIST-SI-000216'
  tag fix_id: 'F-20216r311134_fix'
  tag cci: ['V-100211', 'SV-109315', 'CCI-000381']
  tag nist: ['CM-7 a']
end

