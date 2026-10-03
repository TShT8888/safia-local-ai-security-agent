const params = new URLSearchParams(window.location.search);
const message = params.get("message");

document.querySelector("#preview").innerHTML = message;

function merge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === "object") {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

window.applyPreferences = function applyPreferences(body) {
  return merge({}, body);
};
