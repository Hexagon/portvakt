-- Rewrite repository-relative Markdown links to the generated site pages.
local map = {
  ["GETTING-STARTED.md"] = "index.html",
  ["PLUGINS.md"] = "plugins.html",
  ["SECURITY.md"] = "security.html",
  ["AGENTS.md"] = "agents.html",
  ["plugin-template.toml"] = "../raw/plugin-template.toml",
}
function Link(el)
  if el.target:match("^https?:") then return el end
  local path, anchor = el.target:match("^([^#]*)(#?.*)$")
  local file = path:match("([^/]+)$")
  if file and map[file] then
    el.target = map[file] .. anchor
  elseif path ~= "" and not path:match("^https?:") then
    el.target = "https://github.com/Hexagon/portvakt/blob/main/" .. path:gsub("^%.%./", ""):gsub("^%./", "") .. anchor
  end
  return el
end
