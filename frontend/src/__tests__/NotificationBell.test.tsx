import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

const listNotifications = vi.fn();
const markNotificationRead = vi.fn();
const markAllNotificationsRead = vi.fn();
const getNotificationPrefs = vi.fn();
const putNotificationPrefs = vi.fn();

vi.mock("@/api/notifications", () => ({
  listNotifications: (...a: unknown[]) => listNotifications(...a),
  markNotificationRead: (...a: unknown[]) => markNotificationRead(...a),
  markAllNotificationsRead: (...a: unknown[]) => markAllNotificationsRead(...a),
  getNotificationPrefs: (...a: unknown[]) => getNotificationPrefs(...a),
  putNotificationPrefs: (...a: unknown[]) => putNotificationPrefs(...a),
}));

// Stable fake WS client so the bell can register its onNotification handler.
const fakeWSClient: { onNotification: (n: unknown) => void } = {
  onNotification: () => {},
};

vi.mock("@/api/ws", () => ({
  getWSClient: () => fakeWSClient,
}));

// Spy on navigation so deep-link tests can assert the target route.
const navigateSpy = vi.fn();
vi.mock("react-router-dom", async (importOriginal) => {
  const mod = await importOriginal<typeof import("react-router-dom")>();
  return { ...mod, useNavigate: () => navigateSpy };
});

import { NotificationBell, relativeTime } from "@/components/notifications/NotificationBell";

function renderBell(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

const N1 = {
  id: "ntf_1",
  type: "critical_finding",
  title: "Critical finding",
  message: "A malicious IP was observed.",
  investigation_id: null,
  link: null,
  read: false,
  created_at: "2026-07-21T12:00:00Z",
};

describe("NotificationBell", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listNotifications.mockResolvedValue({ items: [N1], total: 1, unread: 1 });
  });

  it("shows the unread badge count", async () => {
    renderBell(<NotificationBell />);
    expect(await screen.findByTestId("notification-unread-badge")).toHaveTextContent("1");
  });

  it("opens the panel and lists notifications", async () => {
    renderBell(<NotificationBell />);
    const btn = await screen.findByTestId("notification-bell-button");
    await act(async () => {
      fireEvent.click(btn);
    });
    expect(await screen.findByTestId("notification-item-ntf_1")).toBeTruthy();
    expect(screen.getByText("Critical finding")).toBeTruthy();
  });

  it("marks a notification read on click and refreshes", async () => {
    markNotificationRead.mockResolvedValue(undefined);
    renderBell(<NotificationBell />);
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-bell-button"));
    });
    const before = listNotifications.mock.calls.length;
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-item-ntf_1"));
    });
    await waitFor(() => expect(markNotificationRead).toHaveBeenCalledWith("ntf_1"));
    await waitFor(() =>
      expect(listNotifications.mock.calls.length).toBeGreaterThan(before),
    );
  });

  it("marks all read", async () => {
    markAllNotificationsRead.mockResolvedValue({ marked: 1 });
    renderBell(<NotificationBell />);
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-bell-button"));
    });
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-mark-all"));
    });
    await waitFor(() => expect(markAllNotificationsRead).toHaveBeenCalledTimes(1));
  });

  it("hides the badge when there are no unread notifications", async () => {
    listNotifications.mockResolvedValue({ items: [], total: 0, unread: 0 });
    renderBell(<NotificationBell />);
    await waitFor(() => expect(listNotifications).toHaveBeenCalled());
    expect(screen.queryByTestId("notification-unread-badge")).toBeNull();
  });

  it("navigates to the deep link when the notification carries one", async () => {
    markNotificationRead.mockResolvedValue(undefined);
    listNotifications.mockResolvedValue({
      items: [{ ...N1, link: "/hunt" }],
      total: 1,
      unread: 1,
    });
    renderBell(<NotificationBell />);
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-bell-button"));
    });
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-item-ntf_1"));
    });
    await waitFor(() => expect(navigateSpy).toHaveBeenCalledWith("/hunt"));
  });

  it("falls back to the investigation deep-link without an explicit link", async () => {
    markNotificationRead.mockResolvedValue(undefined);
    listNotifications.mockResolvedValue({
      items: [{ ...N1, investigation_id: "inv_9" }],
      total: 1,
      unread: 1,
    });
    renderBell(<NotificationBell />);
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-bell-button"));
    });
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-item-ntf_1"));
    });
    await waitFor(() =>
      expect(navigateSpy).toHaveBeenCalledWith("/investigations/inv_9"),
    );
  });

  it("loads prefs and renders mute toggles behind the gear", async () => {
    getNotificationPrefs.mockResolvedValue({ muted_types: ["noise_digest"] });
    renderBell(<NotificationBell />);
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-bell-button"));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("notification-prefs-toggle"));
    });
    expect(await screen.findByTestId("notification-prefs-panel")).toBeTruthy();
    // Muted type renders unchecked (checkbox = "deliver this type").
    const digest = (await screen.findByTestId(
      "notification-pref-noise_digest",
    )) as HTMLInputElement;
    expect(digest.checked).toBe(false);
    const critical = screen.getByTestId(
      "notification-pref-critical_finding",
    ) as HTMLInputElement;
    expect(critical.checked).toBe(true);
  });

  it("toggling a type PUTs the updated mute list (and unmute removes it)", async () => {
    getNotificationPrefs.mockResolvedValue({ muted_types: ["noise_digest"] });
    putNotificationPrefs
      .mockResolvedValueOnce({ muted_types: ["noise_digest", "critical_finding"] })
      .mockResolvedValueOnce({ muted_types: ["critical_finding"] });
    renderBell(<NotificationBell />);
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-bell-button"));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("notification-prefs-toggle"));
    });
    await screen.findByTestId("notification-pref-critical_finding");

    // Mute critical_finding: PUT with both types.
    await act(async () => {
      fireEvent.click(screen.getByTestId("notification-pref-critical_finding"));
    });
    await waitFor(() =>
      expect(putNotificationPrefs).toHaveBeenCalledWith({
        muted_types: ["noise_digest", "critical_finding"],
      }),
    );

    // Unmute noise_digest: PUT without it.
    await act(async () => {
      fireEvent.click(screen.getByTestId("notification-pref-noise_digest"));
    });
    await waitFor(() =>
      expect(putNotificationPrefs).toHaveBeenLastCalledWith({
        muted_types: ["critical_finding"],
      }),
    );
  });

  it("rolls the toggle back when the PUT fails", async () => {
    getNotificationPrefs.mockResolvedValue({ muted_types: [] });
    putNotificationPrefs.mockRejectedValue(new Error("500"));
    renderBell(<NotificationBell />);
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-bell-button"));
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("notification-prefs-toggle"));
    });
    const digest = (await screen.findByTestId(
      "notification-pref-noise_digest",
    )) as HTMLInputElement;
    expect(digest.checked).toBe(true);
    await act(async () => {
      fireEvent.click(digest);
    });
    // PUT failed — checkbox returns to delivered state.
    await waitFor(() =>
      expect(
        (screen.getByTestId("notification-pref-noise_digest") as HTMLInputElement).checked,
      ).toBe(true),
    );
  });

  it("shows a per-type accent icon and a relative timestamp on each row", async () => {
    const twoMinutesAgo = new Date(Date.now() - 2 * 60 * 1000).toISOString();
    listNotifications.mockResolvedValue({
      items: [
        { ...N1, created_at: twoMinutesAgo },
        {
          ...N1,
          id: "ntf_2",
          type: "hitl_checkpoint",
          title: "Approval Requested",
          created_at: twoMinutesAgo,
        },
      ],
      total: 2,
      unread: 2,
    });
    renderBell(<NotificationBell />);
    await act(async () => {
      fireEvent.click(await screen.findByTestId("notification-bell-button"));
    });
    expect(await screen.findByTestId("notification-icon-ntf_1")).toBeTruthy();
    expect(screen.getByTestId("notification-icon-ntf_2")).toBeTruthy();
    expect(screen.getByTestId("notification-time-ntf_1")).toHaveTextContent("2m ago");
    expect(screen.getByTestId("notification-time-ntf_2")).toHaveTextContent("2m ago");
  });

  it("refreshes when a WS notification arrives", async () => {
    renderBell(<NotificationBell />);
    await waitFor(() => expect(listNotifications).toHaveBeenCalled());
    const before = listNotifications.mock.calls.length;

    // Simulate the hub pushing a per-user notification over the socket.
    await act(async () => {
      fakeWSClient.onNotification({ id: "ntf_live", title: "Live", read: false });
    });

    await waitFor(() =>
      expect(listNotifications.mock.calls.length).toBeGreaterThan(before),
    );
  });
});

describe("relativeTime", () => {
  const now = new Date("2026-07-22T12:00:00Z");

  it("buckets seconds, minutes, hours, and days", () => {
    expect(relativeTime("2026-07-22T11:59:30Z", now)).toBe("just now");
    expect(relativeTime("2026-07-22T11:55:00Z", now)).toBe("5m ago");
    expect(relativeTime("2026-07-22T09:00:00Z", now)).toBe("3h ago");
    expect(relativeTime("2026-07-20T12:00:00Z", now)).toBe("2d ago");
  });

  it("falls back to a locale date beyond a week", () => {
    const out = relativeTime("2026-07-01T12:00:00Z", now);
    expect(out).not.toMatch(/ago|just now/);
    expect(out.length).toBeGreaterThan(0);
  });

  it("returns empty string for an unparsable timestamp", () => {
    expect(relativeTime("not-a-date", now)).toBe("");
  });

  it("clamps future timestamps to 'just now'", () => {
    expect(relativeTime("2026-07-22T12:05:00Z", now)).toBe("just now");
  });
});
