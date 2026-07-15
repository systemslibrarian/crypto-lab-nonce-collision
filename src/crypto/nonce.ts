/**
 * Birthday-bound math for nonce sources — the "how does a nonce ever repeat?"
 * panel. These are exact formulas, computed live from the slider, not baked-in
 * numbers, so a learner can watch the collision probability climb.
 */

/**
 * Probability of at least one collision among `count` uniformly random nonces
 * drawn from a space of 2^bits values (birthday problem):
 *
 *     P ≈ 1 − exp( −count·(count−1) / (2·2^bits) )
 *
 * Returned in [0, 1]. Uses the standard exponential approximation, which is
 * accurate for count ≪ 2^bits (the regime that matters here).
 */
export function collisionProbability(bits: number, count: number): number {
  if (count < 2) return 0;
  const exponent = -(count * (count - 1)) / (2 * Math.pow(2, bits));
  // -expm1(x) = 1 − eˣ without catastrophic cancellation, so the probability
  // stays nonzero even in the astronomically-small regime (96-bit spaces).
  return -Math.expm1(exponent);
}

/**
 * The count at which the collision probability first reaches `p`
 * (default 50%): m ≈ sqrt( 2·2^bits · ln(1/(1−p)) ).
 */
export function countForProbability(bits: number, p = 0.5): number {
  return Math.sqrt(2 * Math.pow(2, bits) * Math.log(1 / (1 - p)));
}

/**
 * NIST SP 800-38D caps a single key at 2³² invocations when 96-bit IVs are
 * generated randomly, bounding the IV-collision probability. This returns that
 * ceiling so the panel can state the real guidance rather than paraphrase it.
 */
export const GCM_RANDOM_IV_LIMIT = Math.pow(2, 32);

/** Format a probability for display: tiny values as "1 in N", else a percentage. */
export function formatProbability(p: number): string {
  if (p <= 0) return '≈ 0 (none yet)';
  if (p >= 0.0001) return `${(p * 100).toPrecision(3)}%`;
  const oneIn = Math.round(1 / p);
  return `1 in ${oneIn.toLocaleString('en-US')}`;
}
