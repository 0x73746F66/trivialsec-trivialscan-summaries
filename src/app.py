import json

import internals
import services.aws


def handler(event, context):
    trigger_object: str = event["Records"][0]["s3"]["object"]["key"]
    internals.logger.info(f"Triggered by {trigger_object}")
    if not trigger_object.startswith(internals.APP_ENV):
        internals.logger.critical(f"Wrong APP_ENV, expected {internals.APP_ENV}")
        return
    if not trigger_object.startswith(f"{internals.APP_ENV}/accounts/"):
        internals.logger.critical("Bad prefix path")
        return
    if not trigger_object.endswith("summary.json"):
        internals.logger.critical("Bad suffix path")
        return

    _, _, account_name, *_ = trigger_object.split("/")
    summary_keys = []
    results = []
    prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/results/"
    try:
        summary_keys = services.aws.list_s3(prefix_key=prefix_key)

    except RuntimeError as err:
        internals.logger.exception(err)
        return

    for summary_key in summary_keys:
        if not summary_key.endswith("summary.json"):
            continue
        if report := internals.ReportSummary(
            account_name=account_name,
            report_id=summary_key.replace(prefix_key, "").replace("/summary.json", ""),
        ).load():
            results.append(report.dict())

    object_key = f"{internals.APP_ENV}/accounts/{account_name}/computed/summaries.json"
    try:
        services.aws.store_s3(
            path_key=object_key, value=json.dumps(results, default=str)
        )

    except RuntimeError as err:
        internals.logger.exception(err)
