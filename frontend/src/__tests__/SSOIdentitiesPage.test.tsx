import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, within, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

// Mock the SSO API module the page depends on. ``ssoProvider`` is read at
// import time for the provider field default, so the factory must supply it.
const listSSOIdentities = vi.fn();
const linkSSOIdentity = vi.fn();
const unlinkSSOIdentity = vi.fn();

vi.mock("@/api/sso", () => ({
  ssoProvider: "okta",
  listSSOIdentities: (...a: unknown[]) => listSSOIdentities(...a),
  linkSSOIdentity: (...a: unknown[]) => linkSSOIdentity(...a),
  unlinkSSOIdentity: (...a: unknown[]) => unlinkSSOIdentity(...a),
}));

import { SSOIdentitiesPage } from "@/components/auth/SSOIdentitiesPage";
import { ApiError } from "@/api/client";

const IDENTITY = {
  id: "sso_01ABC",
  user_id: "usr_01XYZ",
  provider: "okta",
  subject: "00u1a2b3",
  email: "alice@corp.example",
  created_at: "2026-05-01T00:00:00Z",
};

function setInput(testId: string, value: string) {
  fireEvent.change(screen.getByTestId(testId), { target: { value } });
}

// The page renders <Header>, which uses react-router hooks — wrap in a router.
function renderPage(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("SSOIdentitiesPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("disables Load until a user id is entered, then lists identities", async () => {
    listSSOIdentities.mockResolvedValue([IDENTITY]);
    renderPage(<SSOIdentitiesPage />);

    const loadBtn = screen.getByTestId("sso-identities-load-button");
    expect(loadBtn).toBeDisabled();

    setInput("sso-identities-user-input", "usr_01XYZ");
    expect(loadBtn).toBeEnabled();
    fireEvent.click(loadBtn);

    expect(listSSOIdentities).toHaveBeenCalledWith("usr_01XYZ");
    const table = screen.getByTestId("sso-identities-table");
    await waitFor(() =>
      expect(within(table).getByText("00u1a2b3")).toBeInTheDocument()
    );
    expect(within(table).getByText("alice@corp.example")).toBeInTheDocument();
  });

  it("links an identity to the loaded user", async () => {
    listSSOIdentities.mockResolvedValue([]);
    linkSSOIdentity.mockResolvedValue(IDENTITY);
    renderPage(<SSOIdentitiesPage />);

    // Link button stays disabled until a user is loaded.
    expect(screen.getByTestId("sso-identities-link-button")).toBeDisabled();

    setInput("sso-identities-user-input", "usr_01XYZ");
    fireEvent.click(screen.getByTestId("sso-identities-load-button"));

    // Provider defaults to the configured ssoProvider ("okta"); the button
    // enables once a user is loaded AND a subject is supplied.
    setInput("sso-identities-subject-input", "00u1a2b3");
    await waitFor(() =>
      expect(screen.getByTestId("sso-identities-link-button")).toBeEnabled()
    );
    fireEvent.click(screen.getByTestId("sso-identities-link-button"));

    await waitFor(() =>
      expect(linkSSOIdentity).toHaveBeenCalledWith({
        user_id: "usr_01XYZ",
        provider: "okta",
        subject: "00u1a2b3",
        email: null,
      })
    );
  });

  it("surfaces the 409 detail when an identity is already linked", async () => {
    listSSOIdentities.mockResolvedValue([]);
    linkSSOIdentity.mockRejectedValue(
      new ApiError(409, "Conflict", {
        detail: "This IdP identity is already linked to an account",
      })
    );
    renderPage(<SSOIdentitiesPage />);

    setInput("sso-identities-user-input", "usr_01XYZ");
    fireEvent.click(screen.getByTestId("sso-identities-load-button"));
    setInput("sso-identities-subject-input", "dup-subject");
    await waitFor(() =>
      expect(screen.getByTestId("sso-identities-link-button")).toBeEnabled()
    );
    fireEvent.click(screen.getByTestId("sso-identities-link-button"));

    const alert = await screen.findByTestId("sso-identities-error");
    expect(alert).toHaveTextContent(
      "This IdP identity is already linked to an account"
    );
  });

  it("unlinks an identity", async () => {
    listSSOIdentities.mockResolvedValue([IDENTITY]);
    unlinkSSOIdentity.mockResolvedValue(undefined);
    renderPage(<SSOIdentitiesPage />);

    setInput("sso-identities-user-input", "usr_01XYZ");
    fireEvent.click(screen.getByTestId("sso-identities-load-button"));
    const unlinkBtn = await screen.findByTestId(
      `sso-identities-unlink-${IDENTITY.id}`
    );
    fireEvent.click(unlinkBtn);

    expect(unlinkSSOIdentity).toHaveBeenCalledWith(IDENTITY.id);
  });
});
