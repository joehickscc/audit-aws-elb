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

# coreo_uni_util_notify "advise-elb" do
#   action :notify
#   type 'email'
#   allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
#   send_on "${AUDIT_AWS_ELB_SEND_ON}"
#   payload '{"stack name":"INSTANCE::stack_name",
#   "instance name":"INSTANCE::name",
#   "number_of_checks":"STACK::coreo_aws_advisor_elb.advise-elb.number_checks",
#   "number_of_violations":"STACK::coreo_aws_advisor_elb.advise-elb.number_violations",
#   "number_violations_ignored":"STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",
#   "violations": STACK::coreo_aws_advisor_elb.advise-elb.report }'
#   payload_type "json"
#   endpoint ({
#       :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
#   })
# end

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
ret_alerts = {};
ret_table = "[";
var BreakException = {};
num_violations = 0;
num_certs = 0;
for (violation_id in json_input) {
  num_certs++;
    console.log("examining violation: " + violation_id);
            num_violations++;
            raw_alert = json_input[violation_id];
            region = raw_alert["violations"]["elb-old-ssl-policy"]["region"];
            aws_console = "https://console.aws.amazon.com/ec2/v2/home?region=" + region + "#LoadBalancers:search=" + violation_id + "";
            aws_console_html = "<a href=" + aws_console + ">AWS Console</a>";
            //raw_alert["violations"]["elb-old-ssl-policy"]["violating_object"] = {};
            raw_alert["violations"]["elb-old-ssl-policy"]["aws_console"] = aws_console;
            ret_alerts[violation_id] = raw_alert;
            ret_table = ret_table + '{"violation object" : "' + violation_id + '", "region" : "' + region + '", "aws link" : "' + aws_console_html + '"}, ';
            console.log("      object is in violation: " + violation_id);
}
    ret_table = ret_table.replace(/, $/, "");
    ret_table = ret_table + "]";
    ret_obj = JSON.parse(ret_table);
    html = tableify(ret_obj);
    html1 = '<p>Alerts powered by <img src="https://d1qb2nb5cznatu.cloudfront.net/startups/i/701250-e3792035663a30915a0b9ab26293b85b-medium_jpg.jpg?buster=1432673112"></p>';
    //html3 = "<p>Number of ELB SSL Listeners: " + num_certs + "</p><p>Number in Violation: " + num_violations + "</p>";
    html = html1 + html;
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
  <p>number of ELB SSL Listeners: STACK::coreo_aws_advisor_elb.advise-elb.number_checks</p>
  <p>number of ELB SSL Listener violations: STACK::coreo_aws_advisor_elb.advise-elb.number_violations</p>
  <p>number of ignored violations: STACK::coreo_aws_advisor_elb.advise-elb.number_ignored_violations</p>
  <p>stack name: INSTANCE::stack_name</p>
  <p>instance name: INSTANCE::name</p>
  '
  payload_type "html"
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on INSTANCE::stack_name :: INSTANCE::name'
  })
end
