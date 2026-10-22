function applyDefaults(target, req) {
  return Object.assign(target, req.body);
}
