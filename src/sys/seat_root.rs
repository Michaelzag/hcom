//! Bounded ancestry checks for a verified seat owner.
//!
//! These helpers never read or signal a process themselves. Callers supply
//! native process facts and authenticate the owner and recorded root identities.

use super::process_args::EnvRead;

const MAX_ANCESTORS: usize = 16;

/// Missing process facts and unreadable facts both stop an ancestry walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Read<T> {
    Present(T),
    Absent,
    Unreadable,
}

/// Whether `owner` is `root` or reaches it through creation-ordered parent links.
/// No fact above `root` is read, and reserved PIDs are never accepted as roots.
pub(crate) fn descends_from<T: PartialOrd>(
    owner: u32,
    root: u32,
    mut parent: impl FnMut(u32) -> Read<u32>,
    mut creation: impl FnMut(u32) -> Read<T>,
) -> bool {
    if owner <= 1 || root <= 1 {
        return false;
    }
    if owner == root {
        return true;
    }
    let Read::Present(mut current_creation) = creation(owner) else {
        return false;
    };
    let mut current = owner;
    let mut seen = [0; MAX_ANCESTORS + 1];
    seen[0] = owner;
    for depth in 0..MAX_ANCESTORS {
        let Read::Present(pid) = parent(current) else {
            return false;
        };
        if pid <= 1 || seen[..=depth].contains(&pid) {
            return false;
        }
        let Read::Present(parent_creation) = creation(pid) else {
            return false;
        };
        if !matches!(
            parent_creation.partial_cmp(&current_creation),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        ) {
            return false;
        }
        if pid == root {
            return true;
        }
        seen[depth + 1] = pid;
        current = pid;
        current_creation = parent_creation;
    }
    false
}

/// Find the PTY child directly below the nearest verified legacy `hcom pty`.
/// Every process, including the owner, must carry a nonempty bound process ID.
/// A broken chain returns no root, never the last partially verified ancestor.
/// The wrapper itself is never a kill root, even when it is the starting owner.
pub(crate) fn legacy_pty_child_root<T: PartialOrd>(
    owner: u32,
    bound_ids: &[String],
    mut parent: impl FnMut(u32) -> Read<u32>,
    mut creation: impl FnMut(u32) -> Read<T>,
    mut argv: impl FnMut(u32) -> Read<Vec<u8>>,
    mut env_id: impl FnMut(u32) -> EnvRead,
) -> Option<u32> {
    if owner <= 1 || !has_bound_id(env_id(owner), bound_ids) {
        return None;
    }
    let Read::Present(mut current_creation) = creation(owner) else {
        return None;
    };
    let Read::Present(owner_argv) = argv(owner) else {
        return None;
    };
    if is_wrapper(&owner_argv) {
        return None;
    }
    let mut current = owner;
    let mut seen = [0; MAX_ANCESTORS + 1];
    seen[0] = owner;
    for depth in 0..MAX_ANCESTORS {
        let Read::Present(pid) = parent(current) else {
            return None;
        };
        if pid <= 1 || seen[..=depth].contains(&pid) || !has_bound_id(env_id(pid), bound_ids) {
            return None;
        }
        let Read::Present(parent_creation) = creation(pid) else {
            return None;
        };
        if !matches!(
            parent_creation.partial_cmp(&current_creation),
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        ) {
            return None;
        }
        let Read::Present(parent_argv) = argv(pid) else {
            return None;
        };
        if is_wrapper(&parent_argv) {
            return Some(current);
        }
        seen[depth + 1] = pid;
        current = pid;
        current_creation = parent_creation;
    }
    None
}

fn has_bound_id(env_id: EnvRead, bound_ids: &[String]) -> bool {
    matches!(env_id, EnvRead::Present(id) if !id.is_empty() && bound_ids.iter().any(|bound| bound == &id))
}

/// Recognize only exact, NUL-delimited `hcom pty` or `hcom.exe pty` argv.
pub(crate) fn is_wrapper(argv: &[u8]) -> bool {
    if argv.last() != Some(&0) {
        return false;
    }
    let mut args = argv.split(|byte| *byte == 0);
    let executable = args.next().unwrap_or_default();
    let basename = executable
        .rsplit(|byte| matches!(*byte, b'/' | b'\\'))
        .next()
        .unwrap_or_default();
    (basename == b"hcom" || basename == b"hcom.exe") && args.next() == Some(b"pty".as_slice())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    const OWNER: u32 = 50;
    const MIDDLE: u32 = 40;
    const WRAPPER: u32 = 30;
    const ID: &str = "seat-bound-id";

    #[derive(Clone)]
    struct Process {
        parent: Read<u32>,
        creation: Read<u64>,
        argv: Read<Vec<u8>>,
        env_id: Read<String>,
    }

    fn process(parent: u32, creation: u64, args: &[&str]) -> Process {
        let mut argv = args.join("\0").into_bytes();
        argv.push(0);
        Process {
            parent: Read::Present(parent),
            creation: Read::Present(creation),
            argv: Read::Present(argv),
            env_id: Read::Present(ID.to_string()),
        }
    }

    fn chain() -> BTreeMap<u32, Process> {
        BTreeMap::from([
            (OWNER, process(MIDDLE, 500, &["node", "omp.js"])),
            (MIDDLE, process(WRAPPER, 400, &["bun", "omp.js"])),
            (WRAPPER, process(20, 300, &["/usr/local/bin/hcom", "pty"])),
            (20, process(10, 200, &["terminal-emulator"])),
            (10, process(1, 100, &["hcom", "pty"])),
        ])
    }

    fn linear_chain(edges: usize) -> BTreeMap<u32, Process> {
        (0..=edges)
            .map(|depth| {
                let pid = 1000 + depth as u32;
                let args: &[&str] = if depth == edges {
                    &["hcom", "pty"]
                } else {
                    &["interpreter"]
                };
                (pid, process(pid + 1, 1000 - depth as u64, args))
            })
            .collect()
    }

    fn descends(processes: &BTreeMap<u32, Process>, owner: u32, root: u32) -> bool {
        descends_from(
            owner,
            root,
            |pid| {
                processes
                    .get(&pid)
                    .map_or(Read::Absent, |p| p.parent.clone())
            },
            |pid| {
                processes
                    .get(&pid)
                    .map_or(Read::Absent, |p| p.creation.clone())
            },
        )
    }

    fn legacy(processes: &BTreeMap<u32, Process>, owner: u32) -> Option<u32> {
        legacy_pty_child_root(
            owner,
            &[ID.to_string(), "other-bound-id".to_string()],
            |pid| {
                processes
                    .get(&pid)
                    .map_or(Read::Absent, |p| p.parent.clone())
            },
            |pid| {
                processes
                    .get(&pid)
                    .map_or(Read::Absent, |p| p.creation.clone())
            },
            |pid| processes.get(&pid).map_or(Read::Absent, |p| p.argv.clone()),
            |pid| match processes.get(&pid).map(|p| &p.env_id) {
                Some(Read::Present(id)) => EnvRead::Present(id.clone()),
                Some(Read::Unreadable) => EnvRead::Unreadable,
                Some(Read::Absent) | None => EnvRead::Absent,
            },
        )
    }

    #[test]
    fn legacy_finds_pty_child_not_wrapper_or_same_id_ancestors_above_it() {
        assert_eq!(legacy(&chain(), OWNER), Some(MIDDLE));
    }

    #[test]
    fn legacy_never_returns_the_wrapper_itself() {
        assert_eq!(legacy(&chain(), WRAPPER), None);
    }

    #[test]
    fn legacy_returns_owner_when_its_parent_is_the_wrapper() {
        assert_eq!(legacy(&chain(), MIDDLE), Some(MIDDLE));
    }

    #[test]
    fn legacy_requires_a_bound_id_on_owner_and_every_ancestor() {
        for pid in [OWNER, MIDDLE, WRAPPER] {
            for env_id in [
                Read::Absent,
                Read::Unreadable,
                Read::Present(String::new()),
                Read::Present("unbound-id".to_string()),
            ] {
                let mut processes = chain();
                processes.get_mut(&pid).unwrap().env_id = env_id;
                assert_eq!(legacy(&processes, OWNER), None, "unverified process {pid}");
            }
        }
    }

    #[test]
    fn legacy_accepts_each_of_the_rows_bound_ids() {
        let mut processes = chain();
        processes.get_mut(&MIDDLE).unwrap().env_id = Read::Present("other-bound-id".to_string());
        assert_eq!(legacy(&processes, OWNER), Some(MIDDLE));
    }

    #[test]
    fn legacy_rejects_non_monotonic_creation_times() {
        for (pid, creation) in [(MIDDLE, 501), (WRAPPER, 401)] {
            let mut processes = chain();
            processes.get_mut(&pid).unwrap().creation = Read::Present(creation);
            assert_eq!(legacy(&processes, OWNER), None);
        }
    }

    #[test]
    fn legacy_requires_exact_wrapper_executable_and_subcommand() {
        for args in [
            &["hcom", "send"][..],
            &["hcom", "pty-other"],
            &["hcom", "--flag", "pty"],
            &["hcom-other", "pty"],
            &["hcom.cmd", "pty"],
            &["shell", "hcom pty"],
            &["hcom"],
        ] {
            let mut processes = chain();
            processes.insert(WRAPPER, process(1, 300, args));
            assert_eq!(legacy(&processes, OWNER), None, "{args:?}");
        }
    }

    #[test]
    fn legacy_recognizes_windows_executable_paths_on_any_host() {
        let mut processes = chain();
        processes.insert(
            WRAPPER,
            process(20, 300, &[r"C:\Program Files\hcom\hcom.exe", "pty"]),
        );
        assert_eq!(legacy(&processes, OWNER), Some(MIDDLE));
    }

    #[test]
    fn legacy_does_not_accept_unterminated_wrapper_arguments() {
        let mut processes = chain();
        processes.get_mut(&WRAPPER).unwrap().argv = Read::Present(b"hcom\0pty".to_vec());
        processes.get_mut(&WRAPPER).unwrap().parent = Read::Present(1);
        assert_eq!(legacy(&processes, OWNER), None);
    }

    #[test]
    fn legacy_stops_at_the_cap_without_returning_a_partial_ancestor() {
        assert_eq!(
            legacy(&linear_chain(MAX_ANCESTORS), 1000),
            Some(1000 + MAX_ANCESTORS as u32 - 1)
        );
        assert_eq!(legacy(&linear_chain(MAX_ANCESTORS + 1), 1000), None);
    }

    #[test]
    fn legacy_rejects_a_cycle_even_with_equal_creation_times() {
        let mut processes = chain();
        for pid in [OWNER, MIDDLE, WRAPPER] {
            processes.get_mut(&pid).unwrap().creation = Read::Present(300);
        }
        processes.insert(WRAPPER, process(MIDDLE, 300, &["interpreter"]));
        assert_eq!(legacy(&processes, OWNER), None);
    }

    #[test]
    fn legacy_never_accepts_init_even_if_it_looks_like_a_wrapper() {
        let mut processes = chain();
        processes.get_mut(&MIDDLE).unwrap().parent = Read::Present(1);
        processes.insert(1, process(0, 100, &["hcom", "pty"]));
        assert_eq!(legacy(&processes, OWNER), None);
        assert_eq!(legacy(&processes, 1), None);
        assert_eq!(legacy(&processes, 0), None);
    }

    #[test]
    fn legacy_missing_or_unreadable_facts_break_the_entire_chain() {
        for unreadable in [false, true] {
            for pid in [OWNER, MIDDLE, WRAPPER] {
                let mut processes = chain();
                processes.get_mut(&pid).unwrap().creation = if unreadable {
                    Read::Unreadable
                } else {
                    Read::Absent
                };
                assert_eq!(legacy(&processes, OWNER), None);

                let mut processes = chain();
                processes.get_mut(&pid).unwrap().argv = if unreadable {
                    Read::Unreadable
                } else {
                    Read::Absent
                };
                assert_eq!(legacy(&processes, OWNER), None);
            }
            for pid in [OWNER, MIDDLE] {
                let mut processes = chain();
                processes.get_mut(&pid).unwrap().parent = if unreadable {
                    Read::Unreadable
                } else {
                    Read::Absent
                };
                assert_eq!(legacy(&processes, OWNER), None);
            }
        }
    }

    #[test]
    fn descends_from_accepts_the_verified_owner_itself() {
        assert!(descends(&BTreeMap::new(), OWNER, OWNER));
    }

    #[test]
    fn descends_from_reaches_a_two_level_root() {
        let mut processes = chain();
        processes.get_mut(&WRAPPER).unwrap().parent = Read::Unreadable;
        assert!(descends(&processes, OWNER, WRAPPER));
        assert!(!descends(&processes, OWNER, 20));
    }

    #[test]
    fn descends_from_rejects_a_broken_or_unreadable_chain() {
        for unreadable in [false, true] {
            let mut processes = chain();
            processes.get_mut(&MIDDLE).unwrap().parent = if unreadable {
                Read::Unreadable
            } else {
                Read::Absent
            };
            assert!(!descends(&processes, OWNER, WRAPPER));

            for pid in [OWNER, MIDDLE, WRAPPER] {
                let mut processes = chain();
                processes.get_mut(&pid).unwrap().creation = if unreadable {
                    Read::Unreadable
                } else {
                    Read::Absent
                };
                assert!(!descends(&processes, OWNER, WRAPPER));
            }
        }
    }

    #[test]
    fn descends_from_rejects_non_monotonic_creation_times() {
        for (pid, creation) in [(MIDDLE, 501), (WRAPPER, 401)] {
            let mut processes = chain();
            processes.get_mut(&pid).unwrap().creation = Read::Present(creation);
            assert!(!descends(&processes, OWNER, WRAPPER));
        }
    }

    #[test]
    fn creation_order_accepts_equal_times_but_rejects_incomparable_times() {
        let mut processes = chain();
        for pid in [OWNER, MIDDLE, WRAPPER] {
            processes.get_mut(&pid).unwrap().creation = Read::Present(300);
        }
        assert!(descends(&processes, OWNER, WRAPPER));
        assert_eq!(legacy(&processes, OWNER), Some(MIDDLE));
        assert!(!descends_from(
            OWNER,
            WRAPPER,
            |_| Read::Present(WRAPPER),
            |_| Read::Present(f64::NAN),
        ));
        assert_eq!(
            legacy_pty_child_root(
                OWNER,
                &[ID.to_string()],
                |_| Read::Present(WRAPPER),
                |_| Read::Present(f64::NAN),
                |pid| Read::Present(if pid == WRAPPER {
                    b"hcom\0pty\0".to_vec()
                } else {
                    b"interpreter\0".to_vec()
                }),
                |_| EnvRead::Present(ID.to_string()),
            ),
            None
        );
    }

    #[test]
    fn descends_from_respects_the_exact_ancestor_cap() {
        for edges in [MAX_ANCESTORS, MAX_ANCESTORS + 1] {
            assert_eq!(
                descends(&linear_chain(edges), 1000, 1000 + edges as u32),
                edges == MAX_ANCESTORS
            );
        }
    }

    #[test]
    fn descends_from_rejects_cycles_and_reserved_pids() {
        let mut processes = chain();
        processes.get_mut(&OWNER).unwrap().creation = Read::Present(300);
        processes.get_mut(&MIDDLE).unwrap().creation = Read::Present(300);
        processes.get_mut(&MIDDLE).unwrap().parent = Read::Present(OWNER);
        assert!(!descends(&processes, OWNER, WRAPPER));
        for (owner, root) in [(OWNER, 1), (OWNER, 0), (1, 1), (0, 0)] {
            assert!(!descends(&processes, owner, root));
        }
    }
}
