-- detect_gate.lua : utilisé pour lire le prompt et déduire la gate (A/B/…)

msleep(500)
write("\n")

local gate = nil

local patterns = {
  "Sec.*login:",
  "Sec.*>"
}

for i = 1, #patterns do
  local rc, match = expect(patterns[i], 5000)
  if rc == 1 and type(match) == "string" then
    local g = match:match("Sec[%w%-]*%-([A-Z])")
    if g then
      gate = g
      break
    end
  end
end

if gate then
  print("GATE=" .. gate)
else
  print("GATE=?")
end

exit(0)
