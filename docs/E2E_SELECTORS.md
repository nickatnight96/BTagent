# E2E Selector Convention

This file is the contract between the React components and the
Playwright test suite (`tests/e2e/`). Every interactive element gets a
stable `data-testid` so tests survive UI refactors. Aria-labels are
added in the same pass — they cover accessibility for screen readers
*and* unblock axe-core checks in Sprint I.

## Naming pattern

```
data-testid="<surface>-<element>[-<modifier>]"
```

Lower-kebab-case. No PascalCase, no camelCase. No abbreviations
(`button` not `btn`). Modifiers go at the end and identify *which*
instance when there can be more than one (`-{id}`, `-active`,
`-disabled`, `-error`).

### Surface naming

One word per top-level surface. Use the route name when it exists:

| Surface | Used for |
|---|---|
| `login` | `/login` page |
| `nav` | sidebar links (under `Layout`) |
| `header` | top bar |
| `investigation-list` | `/` index |
| `investigation-card` | one card on the list — modifier is the inv id |
| `investigation-workspace` | `/investigations/:id` — root wrapper |
| `agent-chat` | chat panel inside workspace |
| `event-stream` | live WS events panel inside workspace |
| `cost-badge` | the cost meter inside workspace |
| `new-investigation` | the modal opened from the list |
| `ioc-notebook` | `/iocs` page |
| `ioc-detail` | the IOC detail panel |
| `ioc-import` | the import modal |
| `ioc-export` | the STIX export dialog |
| `mitre-matrix` | `/mitre` page |
| `technique-detail` | one technique modal |
| `knowledge` | `/knowledge` page |
| `knowledge-search` | the search box / results |
| `knowledge-doc` | one document card |
| `knowledge-ingest` | the ingest modal |
| `playbook-list` | `/playbooks` page |
| `playbook-builder` | `/playbooks/builder` canvas |
| `playbook-config` | the config panel inside the builder |
| `playbook-yaml` | the YAML editor |
| `playbook-execution` | `/playbooks/:id/execute` page |

### Element naming

These are the words tests will reach for first. Stay consistent:

- Inputs: `-input` (text/number/select/textarea/file/etc — the
  HTML element doesn't matter, the role does)
- Buttons: `-button`
- Toggles / switches: `-toggle`
- Links: `-link`
- Forms: `-form`
- Dialogs / modals: `-dialog`
- Error / warning text: `-error`, `-warning`
- Empty states: `-empty`
- Loading spinners: `-loading`
- Tabs: `-tab` (with modifier for which tab — `-tab-overview`)
- Lists: `-list`; one item: `-item` (with modifier for which item)
- Filter chips: `-filter` (with modifier — `-filter-tlp`)

### Examples

```html
<input data-testid="login-username-input" />
<input data-testid="login-password-input" type="password" />
<button data-testid="login-submit-button">Log in</button>
<div data-testid="login-error" role="alert">{message}</div>

<a data-testid="nav-investigations-link" href="/">Investigations</a>
<a data-testid="nav-mitre-link" href="/mitre">MITRE ATT&CK</a>

<button data-testid="header-user-menu-button">{username}</button>
<button data-testid="header-logout-button">Sign out</button>

<button data-testid="new-investigation-button">New Investigation</button>

<!-- One per investigation in the list -->
<article data-testid={`investigation-card-${inv.id}`}>...</article>

<div data-testid="investigation-workspace">
  <button data-testid="investigation-workspace-tab-overview">Overview</button>
  <button data-testid="investigation-workspace-tab-iocs">IOCs</button>
  <button data-testid="investigation-workspace-tab-mitre">MITRE</button>
  <button data-testid="investigation-workspace-tab-evidence">Evidence</button>
  <button data-testid="investigation-workspace-pause-button">Pause</button>
  <button data-testid="investigation-workspace-stop-button">Stop</button>
</div>

<div data-testid="agent-chat">
  <ol data-testid="agent-chat-message-list">
    <li data-testid={`agent-chat-message-${msg.id}`}>...</li>
  </ol>
  <textarea data-testid="agent-chat-input" />
  <button data-testid="agent-chat-send-button">Send</button>
</div>
```

## Aria-labels

Add an `aria-label` (or `aria-labelledby`) to every interactive element
that is **not** already labelled by visible text. A `<button>Sign
out</button>` doesn't need one — the text is the label. An icon-only
button (`<button>{<XIcon />}</button>`) needs one.

For inputs, prefer `<label htmlFor>` over `aria-label` when there is a
visible label. Use `aria-label` only when the label is intentionally
hidden (search icon, close-modal X, etc.).

## Enforcement

Sprint A also adds an ESLint rule
(`eslint-plugin-testing-library` + a custom rule) that flags
`<button>`, `<input>`, `<select>`, `<textarea>`, and `<a href>` without
a `data-testid` *or* a clearly-derived one (`<button onClick={x}>{name}
</button>` where the visible text disambiguates). The rule is
`warn`-level for the first sprint and promoted to `error` once Sprint
A's instrumentation pass is complete.

Tests reference selectors by `data-testid` only. **No** XPath,
**no** `:nth-child`, **no** raw class names — those break on every
CSS refactor. If a test wants to reach an element that doesn't have a
testid yet, the test author is expected to add one in the same PR.
