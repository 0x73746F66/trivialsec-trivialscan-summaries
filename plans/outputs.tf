output "report_graphs_arn" {
    value = aws_lambda_function.report_graphs.arn
}
output "report_graphs_role" {
  value = aws_iam_role.report_graphs_role.name
}
output "report_graphs_role_arn" {
  value = aws_iam_role.report_graphs_role.arn
}
output "report_graphs_policy_arn" {
  value = aws_iam_policy.report_graphs_policy.arn
}
