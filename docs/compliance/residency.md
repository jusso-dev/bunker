# Australian data residency

Residency covers more than encrypted backup objects: plaintext workspaces, caches, replica storage, control-plane PostgreSQL, audit records, exported reports, logs, telemetry, CI artifacts, credential systems, support access and disaster-recovery copies all need assessment. Encryption does not change where data is stored. Neither `region` in local policy nor `residency = "AU"` in a UI policy enforces location.

| Backend | Australian deployment considerations | Current verification |
| --- | --- | --- |
| Local disk/NAS | Physically locate primary and secondary systems in approved Australian facilities; review remote management, off-site copies and host backups. | Local filesystem behavior exercised; physical geography and NAS durability are operator evidence. |
| AWS S3 | Select an approved Australian AWS Region (for example Sydney `ap-southeast-2`), verify actual bucket location and every replication destination, logs and account controls. | Region is configuration, not an asserted guarantee. No live bucket inspection or object-lock validation performed. |
| Azure Blob | Select an approved Australian region; inspect storage account replication options, failover geography, diagnostic destinations and access/support arrangements. | No account or redundancy-location evidence collected. No Key Vault or Blob immutability validation. |
| Cloudflare R2 | Verify current contractual and technical placement guarantees. An `auto` region or location hint is not an Australian-only jurisdiction guarantee. | No Australian-only claim; do not select R2 for a strict requirement without independent evidence of an applicable guarantee. |
| Google Drive | Verify the organisation's edition, data-region options, covered services and contract. Consumer accounts do not establish an Australian storage boundary. | No Australian-only or immutable-storage claim. |
| OneDrive | Verify Microsoft tenant geography, applicable data-residency terms, covered data and any multi-geo/backup/export destinations. | No tenant inspection; account naming or user location does not prove residency. |

Reference providers' current documentation and contracts, including [AWS Regions](https://docs.aws.amazon.com/general/latest/gr/rande.html), [R2 data location](https://developers.cloudflare.com/r2/reference/data-location/), [Azure geographies](https://azure.microsoft.com/en-us/explore/global-infrastructure/geographies/), [Google Workspace data regions](https://support.google.com/a/answer/9223653), and [Microsoft 365 data locations](https://learn.microsoft.com/en-us/microsoft-365/enterprise/o365-data-locations?view=o365-worldwide). These links are starting points, not a statement that current terms have been independently reviewed.

Keep control-plane/database/logging infrastructure and your credential manager within the approved boundary as well. Disable unneeded external telemetry and avoid real customer data in public CI. Package workflows contain source/binary artifacts, not an approved customer-backup location.

Before approval, record account/tenant IDs, observed resource regions, replication configuration, contract version, access/support locations, encryption/key custody, evidence date and reviewer. Perform a recovery exercise from the intended Australian secondary location. No live geography verification was performed in this task.
