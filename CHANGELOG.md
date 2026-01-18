## v1.1.0 - Expanded Microsoft scope helpers
Strengthens Microsoft OAuth scope mapping by adding planner and Teams aliases alongside refreshed helper dependencies so Graph workflows discover the right permissions more easily.

### Added
- Introduced `planner`, `planner.readonly`, `teams`, `teams.chat`, and `teams.meetings` aliases with their Graph permission sets for richer workflow scopes.

### Changed
- Updated runtime imports to pull the latest `http`, `json`, `log`, and `b64` helpers so protocol helpers stay in sync with the new scope mappings.

## v1.0.2 - Metadata consistency patch
Keeps msauth metadata aligned for Microsoft OAuth scope mapping and Graph helper discovery keywords so downstream tools see the latest patch information.

### Changed
- Updated the package metadata version and keyword set so msauth and Microsoft OAuth helpers report the current patch level.

### Fixed
- Removed the stale release-metadata drift that could mislead scope mapping discovery tooling about the msauth release state.

## v1.0.1 - Semantic documentation markup update
Improves msauth documentation readability and SEO with semantic HTML for the README snapshot and changelog keywords.

### Changed
- Replaced the docs site README and changelog blocks with structured HTML content.
