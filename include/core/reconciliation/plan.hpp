#ifndef KASUMI_RECONCILIATION_PLAN_HPP
#define KASUMI_RECONCILIATION_PLAN_HPP

#include "core/reconciliation/types.hpp"

#include <expected>
#include <span>

namespace kasumi::reconciliation {

// Computes the plan without mutating state.
ReconcileResult reconcile(const Input& input);

// Reinserts pending references and completes their ancestors.
std::expected<Snapshot, Error>
build_publication_tree(Snapshot executed_local_tree,
                       std::span<const NodeRow> pending_storage_rows,
                       const Snapshot& candidate_shared_tree);

// Validates that no plan paths escape the synchronized root.
bool has_safe_paths(const SyncPlan& plan);

} // namespace kasumi::reconciliation

#endif
