output "dashboard_compliance_graphs_arn" {
    value = aws_lambda_function.dashboard_compliance_graphs.arn
}
output "dashboard_compliance_graphs_role" {
  value = aws_iam_role.dashboard_compliance_graphs_role.name
}
output "dashboard_compliance_graphs_role_arn" {
  value = aws_iam_role.dashboard_compliance_graphs_role.arn
}
output "dashboard_compliance_graphs_policy_arn" {
  value = aws_iam_policy.dashboard_compliance_graphs_policy.arn
}
