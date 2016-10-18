coreo_aws_advisor_alert "elb-old-ssl-policy" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-old-ssl-policy.html"
  display_name "ELB is using old SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is not the latest Amazon predefined SSL policy or is a custom ELB SSL policy."
  category "Security"
  suggested_action "Always use the current AWS predefined security policy."
  level "Critical"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.listener_descriptions.policy_names"]
  operators ["!~"]
  alert_when [/ELBSecurityPolicy-2016-08/i]
end

coreo_aws_advisor_elb "advise-elb" do
  alerts ${AUDIT_AWS_ELB_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_ELB_REGIONS}
end

coreo_uni_util_notify "advise-elb" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_ELB_SEND_ON}"
  payload '{"stack name":"INSTANCE::stack_name",
  "instance name":"INSTANCE::name",
  "number_of_checks":"STACK::coreo_aws_advisor_elb.advise-elb.number_checks",
  "number_of_violations":"STACK::coreo_aws_advisor_elb.advise-elb.number_violations",
  "number_violations_ignored":"STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",
  "violations": STACK::coreo_aws_advisor_elb.advise-elb.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end

# ################################################################
# ## finds the instances launched more than 5 minutes ago that do not meet the tags and logic as specified
# ## in the stack variables - returns a HTML table
# ################################################################
#
coreo_uni_util_jsrunner "advise-elb-jsrunner" do
  action :run
  data_type "html"
  packages([
        {
          :name => "tableify",
          :version => "1.0.0"
        }       ])
  json_input 'STACK::coreo_aws_advisor_elb.advise-elb.report'
  function <<-EOH
var tableify = require('tableify');
required_tags = [
    ${AUDIT_AWS_ELB_EXPECTED_TAGS}
];
var style_section = "\
<style>body {\
font-family :arial;\
padding : 0px;\
margin : 0px;\
}\
\
table {\
font-size: 10pt;\
border-top : black 1px solid;\
border-right : black 1px solid;\
/* border-spacing : 10px */\
border-collapse : collapse;\
}\
\
td, th {\
text-align : left;\
vertical-align : top;\
white-space: nowrap;\
overflow: hidden;\
text-overflow: ellipsis;\
border-left : black 1px solid;\
border-bottom: black 1px solid;\
padding-left : 4px;\
padding-right : 4px;\
}\
\
th {\
background-color : #aaaaaa;\
}\
\
td.number {\
color : blue\
}\
\
td.boolean {\
color : green;\
font-style : italic;\
}\
\
td.date {\
color : purple;\
}\
\
td.null:after {\
color : gray;\
font-style : italic;\
content : null;\
}\
</style>\
";
// implement case-insensitive
required_tags_lower = [];
for (var i = 0; i < required_tags.length; i++) {
  required_tags_lower.push(required_tags[i].toLowerCase());
};
required_tags_lower_string = required_tags_lower.toString().replace(/,/g,', ');;
logic = ${AUDIT_AWS_ELB_TAG_LOGIC};
if (logic == "") {logic = "and";}
ret_alerts = {};
ret_table = "[";
var BreakException = {};
num_violations = 0;
num_instances = 0;
for (instance_id in json_input) {
  inst_tags_string = "";
  num_instances++;
    console.log("examining instance: " + instance_id);
    tags = json_input[instance_id]["tags"];
    var tag_names = [];
    for(var i = 0; i < tags.length; i++) {
        //console.log ("  has tag: " + tags[i]['key']);
        // implement case-insensitive
        inst_tag = tags[i]['key'];
        inst_tag = inst_tag.toLowerCase();
        tag_names.push(inst_tag);
        inst_tags_string = inst_tags_string + inst_tag + ", ";
    }
    inst_tags_string = inst_tags_string.replace(/, $/, "");
    num_required = 0;
    num_present = 0;
        for(var i = 0; i < required_tags_lower.length; i++){
            //console.log("    does it have tag " + required_tags_lower[i] + "?");
            if(tag_names.indexOf(required_tags_lower[i]) == -1) {
                //console.log("      it does not.");              
            } else {
              num_present++;
              //console.log("      it does! num_present is now: " + num_present);
            }
        }
        if (logic == "and") {
          needed = required_tags_lower.length;
        } else {
          needed = 1;  
        }
        if (num_present >= needed) {
          console.log("      instance has enough tags to pass. Need: " + needed + " and it has: " + num_present);          
        } else {
            num_violations++;
            raw_alert = json_input[instance_id];
            region = raw_alert["violations"]["ec2-get-all-instances-older-than"]["region"];
            kill_cmd = "aws ec2 terminate-instances --instance-ids " + instance_id;
            //aws_console = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Instances:search=" + instance_id + ";sort=vpcId";
            aws_console = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#Instances:search=" + instance_id + "";
            // leave off the violating_object to reduce size of the json
            aws_console_html = "<a href=" + aws_console + ">AWS Console</a>";
            raw_alert["violations"]["ec2-get-all-instances-older-than"]["violating_object"] = {};
            raw_alert["violations"]["ec2-get-all-instances-older-than"]["kill_script"] = kill_cmd;
            raw_alert["violations"]["ec2-get-all-instances-older-than"]["aws_console"] = aws_console;
            ret_alerts[instance_id] = raw_alert;
            ret_table = ret_table + '{"instance id" : "' + instance_id + '", "region" : "' + region + '", "kill script" : "' + kill_cmd + '", "aws link" : "' + aws_console_html + '","aws tags" : "' + inst_tags_string + '"}, ';
            console.log("      instance is in violation: " + instance_id);
        }

}
    ret_table = ret_table.replace(/, $/, "");
    ret_table = ret_table + "]";
    ret_obj = JSON.parse(ret_table);
    html = tableify(ret_obj);
    // https://www.cloudcoreo.com/img/logo/logo.png
    // https://d1qb2nb5cznatu.cloudfront.net/startups/i/701250-e3792035663a30915a0b9ab26293b85b-medium_jpg.jpg?buster=1432673112
    html1 = '<p>Alerts powered by <img src="https://d1qb2nb5cznatu.cloudfront.net/startups/i/701250-e3792035663a30915a0b9ab26293b85b-medium_jpg.jpg?buster=1432673112"></p>';
    html2 = "<p>AWS tags required: " + required_tags_lower_string + "</p><p>logic: " + logic + "</p>";
    html3 = "<p>Number of Instances: " + num_instances + "</p><p>Number in Violation: " + num_violations + "</p>";
    html = html1 + html2 + html3 + html;
    // add style
    html = style_section + html;
    callback(html);

EOH
end

# send email to recipient that contains the html table of violating instances
#
coreo_uni_util_notify "advise-elb-jsrunner" do
  action :notify
  type 'email'
  allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_ELB_SEND_ON}"
  payload '
  STACK::coreo_uni_util_jsrunner.advise-elb-jsrunner.return
  <p>stack name: INSTANCE::stack_name</p>
  <p>instance name: INSTANCE::name</p>
  '
  payload_type "html"
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end
