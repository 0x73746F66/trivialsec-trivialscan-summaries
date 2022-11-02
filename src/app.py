import internals
import services.aws


def handler(event, context):
    trigger_object: str = event["Records"][0]["s3"]["object"]["key"]
    internals.logger.info(f"Triggered by {trigger_object}")
    if not trigger_object.startswith(internals.APP_ENV):
        internals.logger.critical(f"Wrong APP_ENV, expected {internals.APP_ENV}")
        return
    if not trigger_object.startswith(f"{internals.APP_ENV}/accounts/"):
        internals.logger.critical("Bad path")
        return
    _, _, account_name, *_ = trigger_object.split("/")
    summary_keys = []
    charts = []
    results = []
    prefix_key = f"{internals.APP_ENV}/accounts/{account_name}/results/"  # type: ignore
    try:
        summary_keys = services.aws.list_s3(prefix_key=prefix_key)

    except RuntimeError as err:
        internals.logger.exception(err)
        return []

    chart_data = {
        internals.GraphLabel.PCIDSS3: {"week": [], "month": [], "year": []},
        internals.GraphLabel.PCIDSS4: {"week": [], "month": [], "year": []},
        internals.GraphLabel.NISTSP800_131A_STRICT: {
            "week": [],
            "month": [],
            "year": [],
        },
        internals.GraphLabel.NISTSP800_131A_TRANSITION: {
            "week": [],
            "month": [],
            "year": [],
        },
        internals.GraphLabel.FIPS1402: {"week": [], "month": [], "year": []},
    }
    _data = {"week": 0, "month": 0, "year": 0}
    for summary_key in summary_keys:
        if not summary_key.endswith("full-report.json"):
            continue
        report = internals.FullReport(
            account_name=account_name,  # type: ignore
            report_id=summary_key.replace(prefix_key, "").replace(
                "/full-report.json", ""
            ),
        ).load()
        group_name, range_group, timestamp = internals.date_label(report.date)  # type: ignore
        cur_results = {"group_name": group_name, "timestamp": timestamp}
        for item in report.evaluations:  # type: ignore
            if item.result_level == "pass":
                continue
            for compliance in item.compliance:  # type: ignore
                if compliance.compliance == internals.ComplianceName.PCI_DSS:
                    if compliance.version == "3.2.1":
                        cur_results.setdefault(internals.GraphLabel.PCIDSS3, _data.copy())  # type: ignore
                        cur_results[internals.GraphLabel.PCIDSS3][range_group] += 1  # type: ignore
                    if compliance.version == "4.0":
                        cur_results.setdefault(internals.GraphLabel.PCIDSS4, _data.copy())  # type: ignore
                        cur_results[internals.GraphLabel.PCIDSS4][range_group] += 1  # type: ignore
                if compliance.compliance == internals.ComplianceName.NIST_SP800_131A:
                    if compliance.version == "strict mode":
                        cur_results.setdefault(internals.GraphLabel.NISTSP800_131A_STRICT, _data.copy())  # type: ignore
                        cur_results[internals.GraphLabel.NISTSP800_131A_STRICT][range_group] += 1  # type: ignore
                    if compliance.version == "transition mode":
                        cur_results.setdefault(internals.GraphLabel.NISTSP800_131A_TRANSITION, _data.copy())  # type: ignore
                        cur_results[internals.GraphLabel.NISTSP800_131A_TRANSITION][range_group] += 1  # type: ignore
                if (
                    compliance.compliance == internals.ComplianceName.FIPS_140_2
                    and compliance.version == "Annex A"
                ):
                    cur_results.setdefault(internals.GraphLabel.FIPS1402, _data.copy())  # type: ignore
                    cur_results[internals.GraphLabel.FIPS1402][range_group] += 1  # type: ignore
        results.append(cur_results)

    agg_sums = {}
    for c, _ in chart_data.items():
        agg_sums.setdefault(c, {})
        for r in ["week", "month", "year"]:
            agg_sums[c].setdefault(r, {})
            for _result in results:
                if c not in _result or r not in _result[c]:
                    continue
                key = (_result["group_name"], _result["timestamp"])
                agg_sums[c][r].setdefault(key, [])
                agg_sums[c][r][key].append(_result[c][r])
    for c, g in agg_sums.items():
        for r, d in g.items():
            for group_key, sum_arr in d.items():
                group_name, timestamp = group_key
                if sum(sum_arr) > 0:
                    chart_data[c][r].append(
                        internals.ComplianceChartItem(
                            name=group_name,
                            num=sum(sum_arr),
                            timestamp=timestamp,
                        )
                    )
    for c, d in chart_data.items():
        ranges = set()
        for r in ["week", "month", "year"]:
            if d[r]:
                ranges.add(r)

        charts.append(
            internals.DashboardCompliance(
                label=c, ranges=list(ranges), data=d  # type: ignore
            )
        )

    object_key = f"{internals.APP_ENV}/accounts/{account_name}/computed/dashboard-compliance.json"
    try:
        return services.aws.store_s3(
            path_key=object_key, value=[chart.dict() for chart in charts]
        )

    except RuntimeError as err:
        internals.logger.exception(err)

    return False
