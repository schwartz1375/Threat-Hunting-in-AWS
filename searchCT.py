import boto3
import datetime
import json
import argparse

def get_events(awsprofile, eventName, starttime, endtime):
	try:
		boto3.setup_default_session(profile_name=awsprofile)
		client = boto3.client('cloudtrail')
		resp = client.get_trail(
			Name='events'
		)	
		response = client.lookup_events(
			LookupAttributes=[
				{
				'AttributeKey': 'EventName',
				'AttributeValue': eventName
				}
			],
			StartTime=starttime,
			EndTime=endtime,
			MaxResults=50,
		)
	except Exception as e:
		print(e)
		print("Unable to retrieve CloudTrail events")
		exit(1)
	return response

def get_events_summaries(eventlist, days):
	print("*"*45)
	print("Summary for the last ", days, " days")
	print("The following events were detected:")
	for key in eventlist:
		print(key)
		print("*"*45)

def main():
	parser = argparse.ArgumentParser(description="Search CloudTrail log for signs of a compromise")
	parser.add_argument("profile", type=str, help = "The AWS profile to use")
	parser.add_argument("days", type=int, help = "Number of days back to be searched in CloudTrail (max of 90 days)")
	args = parser.parse_args()
	if args.days > 90:
		print("Days can not be greater than 90")
		exit(1)
	else:
		days = args.days
	awsprofile = args.profile 
	# "look up events that occurred in a region within the last 90 days"
	# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cloudtrail.html#CloudTrail.Client.lookup_events
	interval = datetime.timedelta(days)  
	endtime = datetime.datetime.now()
	starttime = endtime - interval
	eventlist = []
	events = ['AttachInternetGateway', 'AssociateRouteTable', 'CreateRoute', 'DeleteCustomerGateway', 'DeleteInternetGateway',
			'DeleteRoute', 'DeleteDhcpOptions', 'DisassociateRouteTable', 'CreateNetworkAcl', 'CreateNetworkAclEntry', 
			'DeleteNetworkACL', 'ReplaceNetworkAclEntry', 'ReplaceNetworkAclAssociation', 'AuthorizeSecurityGroupIngress',
			'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup', 
			'StopLogging', 'DeleteTrail', 'UpdateTrail', 'MissingTrail', 'PutEventSelectors', 'DeleteGroupPolicy', 'DeleteRole', 
			'DeleteRolePolicy', 'DeleteUserPolicy', 'PutGroupPolicy', 'PutRolePolicy', 'PutUserPolicy', 'CreatePolicyVersion', 
			'SetDefaultPolicyVersion', 'CreateAccessKey', 'CreateLoginProfile', 'UpdateLoginProfile', 'AttachGroupPolicy', 
			'AttachRolePolicy', 'AddUserToGroup', 'UpdateAssumeRolePolicy', 'DeactivateMFADevice', 'DeleteRolePermissionsBoundary']

	print("Attempting to get events from CloudTrail")
	for eventName in events:
		results = get_events(awsprofile, eventName, starttime, endtime)  # result type is dict
		print("*** Searching for: " + eventName)
		if bool(results["Events"]):
			print(json.dumps(results.get('Events', []), indent=4, sort_keys=True, default=str))
			eventlist.append(eventName)
	else:
		print("Return empty events...")
	get_events_summaries(eventlist, days)

if __name__ == "__main__":
    main()
