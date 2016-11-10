coreo_aws_advisor_alert "elb-inventory" do
  action :define
  service :elb
  display_name "ELB Object Inventory"
  description "This rule performs an inventory on all ELB's in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Information"
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
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.listener_descriptions.policy_names"]
  operators ["!~"]
  alert_when [/ELBSecurityPolicy-2016-08/i]
end

coreo_aws_advisor_alert "elb-current-ssl-policy" do
  action :define
  service :elb
  display_name "ELB is using current SSL policy"
  description "Elastic Load Balancing (ELB) SSL policy is the latest Amazon predefined SSL policy"
  category "Information"
  suggested_action "None."
  level "Information"
  objectives ["load_balancers"]
  audit_objects ["load_balancer_descriptions.listener_descriptions.policy_names"]
  operators ["=="]
  alert_when ["ELBSecurityPolicy-2016-08"]
end

coreo_aws_advisor_elb "advise-elb" do
  alerts ${AUDIT_AWS_ELB_ALERT_LIST}
  action :advise
  regions ${AUDIT_AWS_ELB_REGIONS}
end

## This is the normal full notification of the primary recipient.
coreo_uni_util_notify "advise-elb" do
  action :${AUDIT_AWS_ELB_FULL_JSON_REPORT}
  type 'email'
  allow_empty ${AUDIT_AWS_ELB_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_ELB_SEND_ON}"
  payload '{"stack name":"PLAN::stack_name",
  "instance name":"PLAN::name",
  "number_of_checks":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_checks",
  "number_of_violations":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_violations",
  "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",
  "violations": COMPOSITE::coreo_aws_advisor_elb.advise-elb.report }'
  payload_type "json"
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

## This is part of tag parsing code.
coreo_uni_util_jsrunner "tags-to-notifiers-array" do
  action :run
  data_type "json"
  packages([
        {
          :name => "tableify",
          :version => "1.0.0"
        }       ])
  json_input '{"stack_name":"PLAN::stack_name",
                "instance_name":"PLAN::name",
                "violations": COMPOSITE::coreo_aws_advisor_elb.advise-elb.report}'
  function <<-EOH
const results = json_input["violations"];
const stack_name = json_input["stack_name"];
const instance_name = json_input["instance_name"];

let hasTableHeader = false;
let hasPanelHTML = false;

function createTagsStr(tags) {
  let tags_str = '';
  tags.forEach(tag => {
    tags_str += tag['key'] + ', ';
  });
  tags_str = tags_str.replace(/, $/, "");
  return tags_str;
}

function createOwnerTagVal(tags) {
  let owner_tag_val = "${AUDIT_AWS_ELB_ALERT_NO_OWNER_RECIPIENT}" || 'NONE';
  tags.forEach(tag => {
    let hasTagKeyInAuditTag = tag['key'] === '${AUDIT_AWS_ELB_OWNER_TAG}';
    hasTagKeyInAuditTag = true;
    if (hasTagKeyInAuditTag) {
      owner_tag_val = tag['value'];
    }
  });
  return owner_tag_val;
}

function createKbHTML(kb_link) {
  let kb_html = '';
  if (kb_link) {
    kb_html = "<a href=" + kb_link + ">CloudCoreo Knowledge Base</a>";
  }
  return kb_html;
}

function createLayoutColor(level) {
  const colors = { red: '#e53e2b', yellow: '#e49530', dark: '#6b6b6b' };
  if (level == 'Critical') {
    return colors.red;
  }
  console.log(level);
  if (level == 'Warning') {
    return colors.yellow;
  }
  return colors.dark;
}

function createViolationPanelHTML(violation, alertId) {
  const display_name = violation["display_name"] || '';
  const level = violation["level"] || '';
  const category = violation["category"] || '';
  const description = violation["description"] || '';
  const action = violation["suggested_action"] || '';

  const kb_html = createKbHTML(violation["link"]);

  const layoutColor = createLayoutColor(level);

  return `<div style="border:1px solid ` + layoutColor + `;border-left-width:10px;font-family:sans-serif;color:#333333;max-width:700px;font-size: 14px;margin-bottom:20px;">
        <div style="padding: 15px;overflow: hidden;border-bottom:1px solid #d4d4d4;margin-bottom: 15px;">
          <span style="font-size: 18px;font-weight: bold;line-height: 20px;float: left;">
            ` + display_name + `
          </span>
          <span style="float: right;color:#6B6B6B;line-height: 20px;">` + level + `</span>
          <span style="width: 100%;float: left;line-height: 16px;">Alert ID: ` + alertId + `</span>
        </div>
        <div style="padding: 0 15px;">
          <div>
            <i style="line-height: 18px;">Category</i>
            <p style="line-height:16px;margin:0 0 20px;">` + category + `</p>
          </div>
          <div>
          <i style="line-height: 18px;">Description</i>
          <p style="line-height:16px;margin:0 0 20px;">
            ` + description + `
          </p>
        </div>
      </div>
      <div style="background: #e2e2e2; padding: 15px 15px 2px;">
        <i style="line-height: 18px;">Suggested Fix</i>
        <p style="line-height:16px;margin:0 0 20px;">
          ` + action + `
        </p>
        <p>` + kb_html + `</p>
      </div>
    </div>`;
}

function createViolationTableHTML(violation, elb_id, tags_str) {
  const level = violation["level"] || '';
  const region = violation["region"];
  const aws_console = "https://console.aws.amazon.com/ec2/v2/home?region=" + region
      + "#LoadBalancers:search=" + elb_id + "";
  const aws_console_html = "<a href=" + aws_console + ">AWS Console</a>";
  tags_str = tags_str || 'NONE';

  const layoutColor = createLayoutColor(level);

  if (!hasTableHeader) {
    hasTableHeader = true;
    return `<div style="display:flex; flex-wrap: wrap; text-align: center; font-weight: bold; font-family:sans-serif;color:#333333;max-width:711px;font-size: 14px;">
              <div style=" width:calc(25% - 32px);border: 1px solid #e53e2b; border-left-width:10px;padding: 10px;">ELB id</div>
              <div style="  width:calc(25% - 22px);border: 1px solid #e53e2b;padding: 10px;">region</div>
              <div style="  width:calc(25% - 22px);border: 1px solid #e53e2b;padding: 10px;">aws link</div>
              <div style="  width:calc(25% - 22px);border: 1px solid #e53e2b;padding: 10px;">aws tags</div>
          </div>
          <div style="display:flex; flex-wrap: wrap;text-align: center; font-family:sans-serif;color:#333333;max-width:711px;font-size: 14px;">
              <div style="display:flex; flex-wrap:wrap; align-items: center;justify-content: center; width:calc(25% - 32px);border: 1px solid ` + layoutColor + `; border-left-width:10px;padding: 10px;">` + elb_id + `</div>
              <div style="display:flex; flex-wrap:wrap; align-items: center;justify-content: center;  width:calc(25% - 22px);border: 1px solid ` + layoutColor + `;padding: 10px;">` + region + `</div>
              <div style="display:flex; flex-wrap:wrap; align-items: center;justify-content: center;  width:calc(25% - 22px);border: 1px solid ` + layoutColor + `;padding: 10px;">` + aws_console_html + `</div>
              <div style="display:flex; flex-wrap:wrap; align-items: center;justify-content: center;  width:calc(25% - 22px);border: 1px solid ` + layoutColor + `;padding: 10px;"><span style="background-color: rgba(215, 215, 215, 1);padding: 8px;border-radius: 5px; margin:5px 0">` + tags_str + `</span></div>
          </div>`
  } else {
    return ` <div style="display:flex; flex-wrap: wrap;text-align: center; font-family:sans-serif;color:#333333;max-width:711px;font-size: 14px;">
                <div style="display:flex; flex-wrap:wrap; align-items: center;justify-content: center; width:calc(25% - 32px);border: 1px solid ` + layoutColor + `; border-left-width:10px;padding: 10px;">` + elb_id + `</div>
                <div style="display:flex; flex-wrap:wrap; align-items: center;justify-content: center;  width:calc(25% - 22px);border: 1px solid ` + layoutColor + `;padding: 10px;">` + region + `</div>
                <div style="display:flex; flex-wrap:wrap; align-items: center;justify-content: center;  width:calc(25% - 22px);border: 1px solid ` + layoutColor + `;padding: 10px;">` + aws_console_html + `</div>
                <div style="display:flex; flex-wrap:wrap; align-items: center;justify-content: center;  width:calc(25% - 22px);border: 1px solid ` + layoutColor + `;padding: 10px;"><span style="background-color: rgba(215, 215, 215, 1);padding: 8px;border-radius: 5px; margin:5px 0">` + tags_str + `</span></div>
            </div>`;
  }
}

function payloadsCreateArray(elb_id, owner_tag_val, payloads) {
  const violation_keys = Object.keys(results[elb_id]["violations"]);
  violation_keys.forEach(violation_key => {
    if (!payloads.hasOwnProperty(owner_tag_val)) {
      payloads[owner_tag_val] = {};
    }
    if (!payloads[owner_tag_val].hasOwnProperty(violation_key)) {
      payloads[owner_tag_val][violation_key] = {};
      payloads[owner_tag_val][violation_key]["metadata"] = [];
      payloads[owner_tag_val][violation_key]["objects"] = [];
    }
  });
}

function createObjectData(elb_id, owner_tag_val, payloads, tags_str) {
  let violation_keys = Object.keys(results[elb_id]["violations"]);
  const violation_key = violation_keys[0];

  const violation = results[elb_id]["violations"][violation_key];
  const violationTableHTML = createViolationTableHTML(violation, elb_id, tags_str);
  const payloadTableArrayHTML = payloads[owner_tag_val][violation_key]["objects"];

  payloadTableArrayHTML.push(violationTableHTML);
}

function createMetaData(elb_id, owner_tag_val, payloads) {
  let violation_keys = Object.keys(results[elb_id]["violations"]);
  const violation_key = violation_keys[0];

  const violation = results[elb_id]["violations"][violation_key];
  let violationPanelHTML = '';
  if(!hasPanelHTML) {
    hasPanelHTML = true;
    violationPanelHTML = createViolationPanelHTML(violation, elb_id);
  }
  const payloadPanelArrayHTML = payloads[owner_tag_val][violation_key]["metadata"];

  payloadPanelArrayHTML.push(violationPanelHTML);

}

function createPayloads() {
  const payloads = {};

  Object.keys(results).forEach(function (violation) {
    const tags = results[violation]['tags'];
    const tags_str = createTagsStr(tags);
    const owner_tag_val = createOwnerTagVal(tags);
    payloadsCreateArray(violation, owner_tag_val, payloads);
    createMetaData(violation, owner_tag_val, payloads);
    createObjectData(violation, owner_tag_val, payloads, tags_str);
  });

  return payloads;
}

function createNotifierHTML(email, payloads) {
  const emailPanelHTML = payloads[email]['elb-old-ssl-policy']['metadata'][0];
  const emailTableHTML = payloads[email]['elb-old-ssl-policy']['objects'][0];
  const violationHTML = emailPanelHTML + emailTableHTML;
  return violationHTML;
}

function createNotifiers() {
  const payloads = createPayloads();
  const notifiers = [];
  let notifierHTML = '';
  let num_violations = (Object.keys(payloads).length).toString();
  for (let email in payloads) {
    const endpoint = { 'to': email };
    notifierHTML += createNotifierHTML(email, payloads);
    const notifier = {
      'type': 'email',
      'send_on': 'always',
      'allow_empty': 'true',
      'payload_type': 'html',
      'endpoint': endpoint,
      'payload': notifierHTML,
      'num_violations': num_violations
    };
    if (email != "NONE") {
      notifiers.push(notifier);
    }
  }
  return notifiers;
}
let notifiers = createNotifiers();
notifiers = [notifiers[notifiers.length - 1]];

callback(notifiers);
EOH
end

# these two jsrunners are for debug purposes only - they send the internal files to you for debugging
#
coreo_uni_util_notify "advise-jsrunner-file" do
  action :${AUDIT_AWS_ELB_DEBUG_REPORT}
  type 'email'
  allow_empty true
  payload_type "text"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.jsrunner_file'
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'jsrunner file for PLAN::stack_name :: PLAN::name'
  })
end
coreo_uni_util_notify "advise-package" do
  action :${AUDIT_AWS_ELB_DEBUG_REPORT}
  type 'email'
  allow_empty true
  payload_type "json"
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array.packages_file'
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'package.json file for PLAN::stack_name :: PLAN::name'
  })
end

#  "number_of_checks":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_checks",
#  "number_of_violations":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_violations",
# "number_violations_ignored":"COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_ignored_violations",

# This is the summary report of how many alerts were sent to which emails.
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
  send_on 'always'
  payload '
stack name: PLAN::stack_name
instance name: PLAN::name
number_of_checks: COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_checks
number_of_violations: COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_violations
number_violations_ignored: COMPOSITE::coreo_aws_advisor_elb.advise-elb.number_ignored_violations

rollup report:
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_ELB_ALERT_RECIPIENT}', :subject => 'CloudCoreo elb advisor alerts on PLAN::stack_name :: PLAN::name'
  })
end

