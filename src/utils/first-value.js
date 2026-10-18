// Resolves with the first fulfilled, non-empty value. Losing promises keep
// running under their own fetch deadlines but never delay the caller.
function firstValue(promises, fallback) {
  const list = (promises || []).filter(Boolean);
  return new Promise((resolve) => {
    let remaining = list.length;
    if (remaining === 0) return resolve(fallback);
    for (const promise of list) {
      Promise.resolve(promise).then(
        (value) => {
          if (value) return resolve(value);
          if (--remaining === 0) resolve(fallback);
        },
        () => {
          if (--remaining === 0) resolve(fallback);
        }
      );
    }
  });
}

module.exports = { firstValue };
