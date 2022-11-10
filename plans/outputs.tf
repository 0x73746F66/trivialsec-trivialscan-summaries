output "trivialscan_summaries_arn" {
    value = aws_lambda_function.trivialscan_summaries.arn
}
output "trivialscan_summaries_role" {
  value = aws_iam_role.trivialscan_summaries_role.name
}
output "trivialscan_summaries_role_arn" {
  value = aws_iam_role.trivialscan_summaries_role.arn
}
output "trivialscan_summaries_policy_arn" {
  value = aws_iam_policy.trivialscan_summaries_policy.arn
}
