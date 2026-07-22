import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

const listNotifications = vi.fn();
const markNotificationRead = vi.fn();
const markAllNotificationsRead = vi.fn();

vi.mock("@/api/notifications", () => ({
  listNotifications: (...a: unknown[]) => listNotifications(...a),
  markNotificationRead: (...a: unknown[]) => markNotificationRead(...a),
  markAllNotificationsRead: (...a: unknown[]) => markAllNotificationsRead(...a),
}));

// Stable fake WS client so the bell can register its onNotification handler.
const fakeWSClient: { onNotification: (n: unknown) => void } = {
  onNotification: () => {},
};

vi.mock("@/api/ws", () => ({
  getWSClient: () => fakeWSClient,
}));

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
