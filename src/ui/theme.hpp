#ifndef THEME_HPP
#define THEME_HPP

#include <ftxui/screen/color.hpp>

namespace theme {
using ftxui::Color;

inline const Color base = Color::RGB(36, 39, 58);        // #24273a
inline const Color text = Color::RGB(202, 211, 245);     // #cad3f5
inline const Color subtext1 = Color::RGB(184, 192, 224); // #b8c0e0
inline const Color surface0 = Color::RGB(54, 58, 79);    // #363a4f
inline const Color surface1 = Color::RGB(73, 77, 100);   // #494d64
inline const Color green = Color::RGB(166, 218, 149);    // #a6da95
inline const Color lavender = Color::RGB(183, 189, 248); // #b7bdf8
inline const Color mauve = Color::RGB(198, 160, 246);    // #c6a0f6

} // namespace theme

#endif
