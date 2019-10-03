state.var {
  minimum = state.value(),
  maximum = state.value(),
  value = state.value()
}

function constructor()
  minimum:set(25)
  maximum:set(30)
  value:set(27)
end

function set_min(v)
  minimum:set(v)
end

function set_max(v)
  maximum:set(v)
end

function update_value(new_value)
  prev = value:get()
  min = minimum:get()
  max = maximum:get()

  value:set(new_value)

  if new_value > max and prev <= max then
    contract.event("on", prev, new_value)
  elseif new_value < min and prev >= min then
    contract.event("off", prev, new_value)
  end
end

function get_last_state()
  val = value:get()
  -- min = minimum:get()
  max = maximum:get()
  if val > max then
    return "on"
  else
    return "off"
  end
end

--function get_value(a)
--  return value:get()
--end

abi.register(set_min, set_max, update_value, get_last_state)
