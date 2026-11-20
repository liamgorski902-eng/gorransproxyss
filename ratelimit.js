'use strict';

/** Fixed-window, in-memory rate limiter. Good enough for a single free-tier instance. */
class RateLimiter {
  constructor({ limit, windowMs }) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.hits = new Map();
    this.timer = setInterval(() => this.sweep(), Math.max(10_000, windowMs));
    this.timer.unref();
  }

  /** Spends `cost` units for `key`. */
  hit(key, cost = 1) {
    const now = Date.now();
    let entry = this.hits.get(key);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + this.windowMs };
      this.hits.set(key, entry);
    }
    entry.count += cost;
    return {
      allowed: entry.count <= this.limit,
      retryAfterSec: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)),
    };
  }

  sweep() {
    const now = Date.now();
    for (const [key, entry] of this.hits) if (entry.resetAt <= now) this.hits.delete(key);
    // Hard cap so a flood of unique IPs cannot exhaust memory.
    if (this.hits.size > 50_000) this.hits.clear();
  }

  close() {
    clearInterval(this.timer);
  }
}

/** Caps simultaneous proxied requests per client and overall. */
class ConcurrencyGate {
  constructor({ perKey, global }) {
    this.perKey = perKey;
    this.global = global;
    this.total = 0;
    this.byKey = new Map();
  }

  /** Returns a release function, or null if the caller is over its limit. */
  enter(key) {
    const current = this.byKey.get(key) || 0;
    if (current >= this.perKey || this.total >= this.global) return null;
    this.byKey.set(key, current + 1);
    this.total += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.total -= 1;
      const n = (this.byKey.get(key) || 1) - 1;
      if (n <= 0) this.byKey.delete(key);
      else this.byKey.set(key, n);
    };
  }
}

module.exports = { RateLimiter, ConcurrencyGate };
