coreo_aws_advisor_alert "elb-inventory" do
  action :define
  service :elb
  display_name "ELB Object Inventory"
  description "This rule performs an inventory on all ELB's in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.load_balancer_name"]
  operators ["=~"]
  alert_when [//]
end

coreo_aws_advisor_alert "elb-old-ssl-policy" do
  action :define
  service :elb
  link "http://kb.cloudcoreo.com/mydoc_elb-old-ssl-policy.html"
  display_name "ELB is using old SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is not the latest Amazon predefined SSL policy or is a custom ELB SSL policy."
  category "Security"
  suggested_action "Always use the current AWS predefined security policy."
  level "Critical"
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "!~"]
  alert_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
end

coreo_aws_advisor_alert "elb-current-ssl-policy" do
  action :define
  service :elb
  display_name "ELB is using current SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is the latest Amazon predefined SSL policy"
  category "Informational"
  suggested_action "None."
  level "Information"
  id_map "modifiers.load_balancer_name"
  objectives     ["load_balancers", "load_balancer_policies" ]
  audit_objects  ["", "policy_descriptions"]
  call_modifiers [{}, {:load_balancer_name => "load_balancer_descriptions.load_balancer_name"}]
  formulas       ["", "jmespath.[].policy_attribute_descriptions[?attribute_name == 'Reference-Security-Policy'].attribute_value"]
  operators      ["", "=~"]
  alert_when     ["", /\[\"?(?:ELBSecurityPolicy-2016-08)?\"?\]/]
end

coreo_aws_advisor_alert "elb-health-check-interval" do
  action :define
  service :elb
  display_name "ELB Health Check Interval"
  description "This rule checks the interval of the ELB health check to ensure that it is not too long between health checks."
  category "Health"
  suggested_action "Lower the ELB health check interval to ensure that you are checking your ELBs frequently enough."
  level "Warning"
  objectives ["load_balancers"]
  audit_objects ["object.load_balancer_descriptions.health_check.interval"]
  operators [">"]
  alert_when [1]
end

coreo_aws_advisor_elb "advise-elb" do
  alerts ${AUDIT_AWS_ELB_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_ELB_REGIONS}
end


=begin
  AWS ELB START METHODS
  JSON SEND METHOD
  HTML SEND METHOD
=end
coreo_uni_util_notify "advise-elb-json" do
  action :${AUDIT_AWS_ELB_FULL_JSON_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_ELB_SEND_ON}"
  payload '{"composite name":"PLAN::stack_name",
  "plan name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_elb.advise-elb.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

coreo_uni_util_jsrunner "tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.1.1"
               }       ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "number_of_checks":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_checks",
                "number_of_violations":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_violations",
                "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",
                "violations": COMPOSITE::coreo_aws_advisor_elb.advise-elb.report}'
  function <<-EOH
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditElb = new CloudCoreoJSRunner(json_input, false, "${AUDIT_AWS_ELB_ALERT_RECIPIENT_2}", "${AUDIT_AWS_ELB_OWNER_TAG}", 'elb');
const notifiers = AuditElb.getNotifiers();
callback(notifiers);
  EOH
end

coreo_uni_util_jsrunner "tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.return'
  function <<-EOH
var rollup_string = "";
for (var entry=0; entry < json_input.length; entry++) {
  console.log(json_input[entry]);
  if (json_input[entry]['endpoint']['to'].length) {
    console.log('got an email to rollup');
    rollup_string = rollup_string + "recipient: " + json_input[entry]['endpoint']['to'] + " - " + "nViolations: " + json_input[entry]['num_violations'] + "\\n";
  }
}
callback(rollup_string);
  EOH
end

coreo_uni_util_notify "advise-elb-to-tag-values" do
  action :${AUDIT_AWS_ELB_OWNERS_HTML_REPORT}
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.return' 
end

coreo_uni_util_notify "advise-elb-rollup" do
  action :${AUDIT_AWS_ELB_ROLLUP_REPORT}
  type 'email'
  allow_empty true
  send_on '${AUDIT_AWS_ELB_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
number_of_checks: COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_checks
number_of_violations: COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_violations
number_violations_ignored: COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_ignored_violations

rollup report:
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT_2}', :subject => 'CloudCoreo elb advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end
=begin
  AWS ELB END
=end


