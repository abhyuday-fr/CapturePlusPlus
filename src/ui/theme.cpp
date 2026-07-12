#include "theme.hpp"

MenuOption menuOption;
menuOption.entries.transform = [](EntryState state) {
  Element e = text(state.label) | hcenter;

  if (state.active) {
    e = e | color(theme::base) | bgcolor(theme::green) | bold;
  } else {
    e = e | color(theme::text);
  }

  return e | border;
};

auto menu = Menu(&lines, &selected, menuOption);

auto layout = Renderer(menu, [&] {
  return vbox({
             text("CapturePlusPlus  |  packets: " +
                  std::to_string(lines.size())) |
                 bold | color(theme::lavender),
             separator() | color(theme::surface1),
             menu->Render() | vscroll_indicator | frame | flex,
         }) |
         border | color(theme::surface1) | bgcolor(theme::base);
});
