var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Public IP Address EC2 Instances',
    category: 'EC2',
    domain: 'Compute',
    severity: 'High',
    description: 'Ensures that EC2 instances do not have public IP address attached.',
    more_info: 'EC2 instances should not have a public IP address attached in order to block public access to the instances.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html',
    recommended_action: 'Remove the public IP address from the EC2 instances to block public access to the instance',
    apis: ['EC2:describeInstances', 'STS:getCallerIdentity', 'EC2:describeSecurityGroups'],
    realtime_triggers: ['ec2:RunInstances','ec2:AuthorizeSecurityGroupIngress','ec2:ModifySecurityGroupRules', 'ec2:TerminateInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);

# ...
                    if (element.PublicIpAddress && element.PublicIpAddress.length && openSg) {
                        helpers.addResult(results, 2,
                            `EC2 instance "${element.InstanceId}" has a public IP address attached`,
                            region, resource);
                    } else if (element.PublicIpAddress && element.PublicIpAddress.length && !openSg) {
                        helpers.addResult(results, 0,
                            `EC2 instance "${element.InstanceId}" has a public IP address attached but attached security group is not open to public`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            `EC2 instance "${element.InstanceId}" does not have a public IP address attached`,
                            region, resource);
                    }
                });
            });
