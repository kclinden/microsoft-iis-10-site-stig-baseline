# microsoft-iis-10-site-stig-baseline  
InSpec profile to validate the secure configuration of Microsoft Internet Information Services (IIS) 10.0 Server, against [DISA](https://public.cyber.mil)'s Microsoft IIS 10.0 Site Security Technical Implementation Guide (STIG) Version 2, Release 1.

## Running This Profile
The profile can be ran be using the below command.
```
inspec exec https://github.com/kclinden/microsoft-iis-10-site-stig-baseline.git -t winrm://$server --user $user --password $pass --reporter cli
```

## STIG Coverage

Total Stig Rule Coverage: 52 of 60 rules are automated; 87%  

High (CAT I): 13 of 13 rules are automated  
Medium (CAT II): 37 of 46 rules are automated  
Low (CAT III): 1 of 1 rules are automated  

### Document / Manual Rules (Not Automated)
| StigRuleId |	Severity |
| ----------- | ----------- |
| V-218740 |	Medium |
| V-218744|	Medium |
| V-218764 | Medium | 
| V-218767 | Medium |
| V-218771 | Medium |
| V-218779 | Medium |
| V-218780 | Medium |
| V-218782 | Medium |

## Info

Name: microsoft-iis-10-site-stig-baseline  
Author: Kasey Linden  
Status: accepted on 2020-09-25  
Copyright: N/A  
Copyright Email: N/A
Version: 2  
Release: 1  
Benchmark Date: 23 Oct 2020  
Reference: https://public.cyber.mil  
Reference by: DISA  
