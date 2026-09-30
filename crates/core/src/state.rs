#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Created,
    ResolvingSource,
    Downloading,
    HashChecking,
    WaitingDevice,
    ReadyToInstall,
    Installing,
    Verifying,
    Installed,
    Failed,
    Canceled,
}

pub fn transition(current: Phase, next: Phase) -> Result<Phase, Phase> {
    let ok = matches!(
        (current, next),
        (Phase::Created, Phase::ResolvingSource | Phase::Canceled | Phase::Failed)
            | (
                Phase::ResolvingSource,
                Phase::Downloading | Phase::HashChecking | Phase::Failed | Phase::Canceled
            )
            | (Phase::Downloading, Phase::HashChecking | Phase::Failed | Phase::Canceled)
            | (
                Phase::HashChecking,
                Phase::WaitingDevice | Phase::Failed | Phase::Canceled
            )
            | (
                Phase::WaitingDevice,
                Phase::ReadyToInstall | Phase::Failed | Phase::Canceled
            )
            | (
                Phase::ReadyToInstall,
                Phase::Installing | Phase::Canceled | Phase::Failed
            )
            | (Phase::Installing, Phase::Verifying | Phase::Failed)
            | (Phase::Verifying, Phase::Installed | Phase::Failed)
    );
    if ok {
        Ok(next)
    } else {
        Err(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_hap_skips_download() {
        let mut phase = Phase::Created;
        for next in [
            Phase::ResolvingSource,
            Phase::HashChecking,
            Phase::WaitingDevice,
            Phase::ReadyToInstall,
            Phase::Installing,
            Phase::Verifying,
            Phase::Installed,
        ] {
            phase = transition(phase, next).unwrap();
        }
        assert_eq!(phase, Phase::Installed);
    }

    #[test]
    fn cannot_mark_success_without_verify() {
        assert!(transition(Phase::Installing, Phase::Installed).is_err());
    }
}
