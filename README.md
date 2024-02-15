# ThreatManagementExplorer
PowerShell for Threat Management Explorer

```
$days = 29
$FromDateTime = [DateTime]::UtcNow.AddDays(-$days)
$ToDateTime = [DateTime]::UtcNow

$authSession = Get-SecurityAPISession -domain "byer.com" -credential (get-credential)

$MaliciousEmailsReport = Get-MaliciousEmailsRemovedAfterDelivery -authSession $authSession -FromDateTime $FromDateTime -ToDateTime $ToDateTime
$AllThreatInstances = $MaliciousEmailsReport.resultData.ThreatInstances

$AllThreatInstances[0]
Key                                : abcd1234-abcd-1234-a123-123456abcdef-18436163343134503647-1
NetworkMessageId                   : abcd1234-abcd-1234-a123-123456abcdef
Timestamp                          : 2/2/2024 8:00:46 AM
InternetMessageId                  : <abcd1234.abcd1234@abc-123-1>
RemediationId                      :
Sender                             : someone@example.com
P1Sender                           : someone@example.com
P2Sender                           : someone@example.com
P1SenderDomain                     : example.com
P2SenderDomain                     : example.com
P2SenderDisplayName                : Premier Security Solutions
Recipients                         : {someone@domain.com}
OriginalRecipients                 :
SenderIp                           : 111.107.94.111
SenderDomain                       : example.com
DeliveryLocation                   : 1
CurrentDeliveryLocation            : 1
Subject                            : SUBJECT
ProtectionStatus                   : 2
IsMalware                          : False
IsPhish                            : False
CurrentMalwareVerdictCode          : 0
CurrentSpamVerdictCode             : 0
CurrentPhishConfidence             :
PhishConfidence                    :
CurrentPhishVerdictCode            : 0
ContentType                        : 1
TTResult                           :
AttachmentData                     : {}
ThreatDetectionMethods             : {}
CurrentThreatDetectionMethods      : {}
CurrentMessageActionCode           : 2
AggregatedAdditionalMailEventTypes : {NONE}
AggregatedFilterInfoVerdict        : {}
AggregatedXmiFilterControl         : {}
AggregatedRemediationResults       : {}
MailLanguage                       : en
HubName                            : ABCD12345
InternalId                         : 1234567890
BodyFingerprintBin1                : 2345678901
EnrichedUser                       :
EnrichedSender                     : @{Department=; JobTitle=; Location=; Name=; Upn=; Classifications=}
EnrichedRecipients                 :
UrlDatas                           : {@{NormalizedUrlHash=1234567890; FullUrl=}}
AlertIds                           : {}
ETRs                               : {}
DlpRules                           : {}
InboundConnector                   :
TenantAllowBlockResults            : {}
AntispamDirection                  : 1
XmiInfo                            : @{FinalVerdict=NotSpam; FinalFilterVerdict=NotSpam; FinalVerdictSource=Filters; TenantPolicyFinalVerdict=; TenantPolicyFinalVerdictSource=; UserPolicyFinalVerdict=; UserPolicyFinalVerdictSource=; PhishUrlsDetected=System.Object[]; MalwareUrlsDetected=System.Object[];
                                     SpamUrlsDetected=System.Object[]; MalwareFilterControl=; PhishFilterControl=; SpamFilterControl=; FilterContext=System.Object[]}
MailEvents                         : {@{EventResult=; EventStatus=; EventType=OriginalDelivery; Action=Delivered; DeliveryFolder=Custom}}
AttachmentCount                    : 0
UrlCount                           : 1
Size                               : 54396
RecipientDomains                   : {domain.com}
```

```
$localDate = "Date {0}" -f (Get-TimeZone).ToString().split(' ')[0]

$(foreach ($ThreatInstance in $AllThreatInstances) {
[pscustomobject][ordered]@{
$localDate = [datetime]("{0} {1}" -f $ThreatInstance.TimeStamp.ToShortDateString(), [System.TimeZoneInfo]::ConvertTimeFromUtc($ThreatInstance.Timestamp.ToLongTimeString(), (Get-TimeZone)).ToLongTimeString())
'Subject'= $ThreatInstance.Subject
'Recipients'= $ThreatInstance.Recipients
'Recipient Domains'= $ThreatInstance.RecipientDomains
'Sender address'= $ThreatInstance.Sender
'Sender display name'= $ThreatInstance.P2SenderDisplayName
'Sender domain'= $ThreatInstance.SenderDomain
'Sender IP'= $ThreatInstance.SenderIp
'Sender mail from address'= $ThreatInstance.P1Sender
'Sender mail from domain'= $ThreatInstance.P1SenderDomain
'Additional actions'= $ThreatInstance.MailEvents[1].EventType
'Delivery action'= $ThreatInstance.MailEvents[0].action
'Latest delivery location'= $ThreatInstance.MailEvents[1].DeliveryFolder
'Original delivery location'= $ThreatInstance.MailEvents[0].DeliveryFolder
'Tenant system override(s)'= $ThreatInstance.XmiInfo.TenantPolicyFinalVerdict, $ThreatInstance.XmiInfo.TenantPolicyFinalVerdictSource
'Alert ID'= $ThreatInstance.AlertIds
'Internet message ID'= $ThreatInstance.InternetMessageId
'Network message ID'= $ThreatInstance.NetworkMessageId
'Mail language'= $ThreatInstance.MailLanguage
'Threats'= $ThreatInstance.XmiInfo.FinalVerdict
'Detection technologies'= $ThreatInstance.XmiInfo.PhishFilterControl
'Attachment Count'=$ThreatInstance.AttachmentCount
'URL Count'=$ThreatInstance.UrlCount
'Email size'=$ThreatInstance.Size
'Directionality'= $ThreatInstance.AntispamDirection
'Connector'= $ThreatInstance.InboundConnector
'Data loss prevention rule'= $ThreatInstance.DlpRules
}

}) | ft -a
```
