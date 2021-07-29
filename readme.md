## Threat Hunting in AWS 
Threat hunting – Making the jump from alert-based investigation to threat hunting 

When thinking about threat hunting, we needs to create a threat hunting strategy for the environment they will be operating in.  In this case, AWS,  executing at scale with efficiency, is critical.  Capabilities to hunt are also tied to the [teams maturity](http://detect-respond.blogspot.com/2015/10/a-simple-hunting-maturity-model.html). 

First, let's define threat hunting…its more than just looking at a SEIM or randomly digging through logs.  It is a proactive, hypothesis-driven approach to detecting unknown threats (detect threats not captured by your deployed security tools).  Hunting requires the input of human analysts, often driven by automation to address scale to find what is missed by automated reactive alerting systems.  Hunting leverages diverse types of data to include the cloud service provider sources.  The following are AWS Security Sources:
* AWS CloudTrail  
* Amazon CloudWatch Events  
* Amazon GuardDuty Findings  
* Amazon VPC Flow Logs  
* Amazon Inspector Findings  
* DNS Logs 

## Key AWS tools 
* [AWS CloudTrail](https://aws.amazon.com/cloudtrail/) "provides event history of your AWS account activity, including actions taken through the AWS Management Console, AWS SDKs, command line tools, and other AWS services." 
* [Amazon CloudWatch](https://aws.amazon.com/cloudwatch/) provides dashboards and alerting. 
* [Amazon Athena](https://aws.amazon.com/athena/?whats-new-cards.sort-by=item.additionalFields.postDateTime&whats-new-cards.sort-order=desc) Athena is serverless offering that provides “an interactive query service that makes it easy to analyze data in Amazon S3 using standard SQL”. 

## Threat Hunting CloudTrail using the CLI 
To parse CloudTrail logs, the following tools are needed [jq](https://stedolan.github.io/jq/), gunzip, uniq and sort.   

For example looking for access secret in Secrets Manager
```
gunzip -c *.json.gz | jq -cr '.Records[]| select(.eventName == "GetSecretValue")'
```
For more examples see the Medium article on [Quick and Dirty CloudTrail Threat Hunting Log Analysis](https://medium.com/@george.fekkas/quick-and-dirty-cloudtrail-threat-hunting-log-analysis-b64af10ef923)

Note that a GuardDuty finding or CloudTrail log entry showing a HIDDEN_DUE_TO_SECURITY_REASONS is because AWS doesn’t log username for failed sign-in due to an incorrect user name. 

## searchCT.py
An example python script that leverages [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) to lookup CloudTrail events that are potential signs of an account compromise (in a specific region based on the profile) within the last 90 days. 

Examples
```
python3 ./searchCT.py awsprofile 5
```

## CloudWatch_Logs_Insights_query.txt
This query selects CloudTrail records that contain API Calls that may be indicative of AWS Account Compromise. This is based on multiple concepts and insights from AWS Escalation methods posted by [Rhino Security Labs](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) 

## NOTICE
This is by no means an exhaustive list of API calls (for example, one might want to add UpdateFunctionCode)! I recommend understanding the environment risks and threats (threat modeling) to determine what APIs calls should be considered in scope. Second, the results from these tools should NOT be used as the sole criteria for deciding if one AWS Account has been compromised.

## Additional Resources
* [AWS Incident Response with Athena](https://easttimor.github.io/aws-incident-response/)
* [Threat Hunting with CloudTrail and GuardDuty in SPlunk](https://www.chrisfarris.com/post/reinforce-threat-hunting/)