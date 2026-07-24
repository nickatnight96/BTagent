/**
 * Unit tests for the UC-5.2 notebook-table helpers (#108): pinned-first
 * ordering and the annotation badge row rendered under each IOC value.
 */
import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { pinnedFirst, AnnotationBadges } from "@/components/iocs/IOCNotebook";
import type { IOC } from "@/types/ioc";

function ioc(id: string, extra: Partial<IOC> = {}): IOC {
  return {
    id,
    type: "domain",
    value: `${id}.example.com`,
    source: "unit-test",
    confidence: 0.5,
    first_seen: "2026-07-01T00:00:00Z",
    ...extra,
  };
}

describe("pinnedFirst", () => {
  it("surfaces pinned IOCs while preserving relative order within groups", () => {
    const items = [
      ioc("a"),
      ioc("b", { pinned: true }),
      ioc("c"),
      ioc("d", { pinned: true }),
    ];
    expect(pinnedFirst(items).map((i) => i.id)).toEqual(["b", "d", "a", "c"]);
    // Input untouched (new array).
    expect(items.map((i) => i.id)).toEqual(["a", "b", "c", "d"]);
  });

  it("is a no-op when nothing is pinned", () => {
    const items = [ioc("a"), ioc("b"), ioc("c")];
    expect(pinnedFirst(items).map((i) => i.id)).toEqual(["a", "b", "c"]);
  });
});

describe("AnnotationBadges", () => {
  it("renders pin, disposition, and capped tag badges", () => {
    render(
      <AnnotationBadges
        ioc={ioc("x", {
          pinned: true,
          disposition: "confirmed_malicious",
          tags: ["c2", "phishing", "apt", "wave2"],
        })}
      />,
    );
    expect(screen.getByTestId("ioc-pin-x")).toBeTruthy();
    expect(screen.getByTestId("ioc-disposition-x").textContent).toBe("malicious");
    const wrap = screen.getByTestId("ioc-annotation-badges-x");
    // 3 tag badges + a "+1" overflow marker.
    expect(wrap.textContent).toContain("c2");
    expect(wrap.textContent).toContain("apt");
    expect(wrap.textContent).not.toContain("wave2");
    expect(wrap.textContent).toContain("+1");
  });

  it("renders nothing for an un-annotated IOC", () => {
    const { container } = render(<AnnotationBadges ioc={ioc("y")} />);
    expect(container.firstChild).toBeNull();
  });
});
