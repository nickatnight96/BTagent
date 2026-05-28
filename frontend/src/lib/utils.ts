import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Classname utility used by every UI component.
 *
 * `clsx` resolves conditional/array/object class inputs to a single string;
 * `twMerge` then dedupes conflicting Tailwind utilities so the *last*
 * variant wins. Example: cn("px-2 py-1", "px-4") => "py-1 px-4".
 */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
