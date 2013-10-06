import sublime, sublime_plugin

from threading import Timer
from .complete.complete import get_completions, get_diagnostics, get_usage, get_definition, get_type, reparse, free_tu, free_all
import os, re, sys


#
#
# Retrieve options from cmake
#
#
def parse_flags(f, pflags=[]):
    flags = []
    flag_set = set(pflags)
    def check_include(word):
        if word.startswith('-I') or word.startswith("-D"):
            return word not in flag_set
        else:
            return word != '-g'

    for line in open(f).readlines():
        if line.startswith('CXX_FLAGS') or line.startswith('CXX_DEFINES'):
            words = line[line.index('=')+1:].split()
            flags.extend([word for word in words if check_include(word)])
    print(flags)
    return flags

def accumulate_options(path):
    flags = []
    for root, dirs, filenames in os.walk(path):
        for f in filenames:
            if f.endswith('flags.make'): flags.extend(parse_flags(os.path.join(root, f), flags))
    return flags

project_options = {}

def get_options(project_path, additional_options, build_dir, default_options):
    if project_path in project_options: return project_options[project_path]

    build_dir = os.path.join(project_path, build_dir)
    if os.path.exists(build_dir):
        project_options[project_path] = ['-x', 'c++'] + accumulate_options(build_dir) + additional_options
    else:
        project_options[project_path] = ['-x', 'c++'] + default_options + additional_options

    return project_options[project_path]

#
#
# Retrieve include files
#
#

project_includes = {}

def search_include(path):
    start = len(path)
    if path[-1] is not '/': start = start + 1
    result = []
    for root, dirs, filenames in os.walk(path):
        for f in filenames:
            full_name = os.path.join(root, f)
            result.append(full_name[start:])
    return result

def find_includes(project_path):
    result = set()
    is_path = False
    for option in get_options(project_path):
        if option == '-isystem': is_path = True
        else: is_path = False
        if option.startswith('-I'): result.update(search_include(option[2:]))
        if is_path: result.update(search_include(option))
    project_includes[project_path] = sorted(result)

def complete_includes(project_path, prefix):
    pass


#
#
# Error panel
#
#
class ClangTogglePanel(sublime_plugin.WindowCommand):
    def run(self, **args):
        show = args["show"] if "show" in args else None

        if show or (show == None and not clang_error_panel.is_visible(self.window)):
            clang_error_panel.open(self.window)
        else:
            clang_error_panel.close()


class ClangErrorPanelFlush(sublime_plugin.TextCommand):
    def run(self, edit, data):
        self.view.erase(edit, sublime.Region(0, self.view.size()))
        self.view.insert(edit, 0, data)


class ClangErrorPanel(object):
    def __init__(self):
        self.view = None
        self.data = ""

    def set_data(self, data):
        self.data = data
        if self.is_visible(): self.flush()

    def get_view(self):
        return self.view

    def is_visible(self, window=None):
        ret = self.view != None and self.view.window() != None
        if ret and window:
            ret = self.view.window().id() == window.id()
        return ret

    def set_view(self, view):
        self.view = view

    def flush(self):
        self.view.set_read_only(False)
        self.view.set_scratch(True)
        self.view.run_command("clang_error_panel_flush", {"data": self.data})
        self.view.set_read_only(True)

    def open(self, window=None):
        if window == None:
            window = sublime.active_window()
        if not self.is_visible(window):
            self.view = window.get_output_panel("clangcomplete")
            self.view.settings().set("result_file_regex", "^[ ]*(..[^:\n]*):([0-9]+):?([0-9]+)?:? (.*)$")
            self.view.set_syntax_file('Packages/ClangComplete/ErrorPanel.tmLanguage')
        self.flush()

        window.run_command("show_panel", {"panel": "output.clangcomplete"})

    def close(self):
        sublime.active_window().run_command("hide_panel", {"panel": "output.clangcomplete"})


clang_error_panel = ClangErrorPanel()

#
#
# Get language from sublime
#
#

language_regex = re.compile("(?<=source\.)[\w+#]+")

def get_language(view):
    caret = view.sel()[0].a
    language = language_regex.search(view.scope_name(caret))
    if language == None:
        return None
    return language.group(0)


def is_supported_language(view):
    language = get_language(view)
    if language == None or (language != "c++" and
                            language != "c" and
                            language != "objc" and
                            language != "objc++"):
        return False
    return True




member_regex = re.compile(r"(([a-zA-Z_]+[0-9_]*)|([\)\]])+)((\.)|(->))$")

# def is_member_completion(view, caret):
#     line = view.substr(Region(view.line(caret).a, caret))
#     if member_regex.search(line) != None:
#         return True
#     elif get_language(view).startswith("objc"):
#         return re.search(r"\[[\.\->\s\w\]]+\s+$", line) != None
#     return False

def get_settings():
    return sublime.load_settings("ClangComplete.sublime-settings")

def get_setting(view, key, default=None):
    s = view.settings()
    if s.has("clangcomplete_%s" % key):
        return s.get("clangcomplete_%s" % key)
    return get_settings().get(key, default)

def get_args(view):
    project_path = view.window().folders()[0]
    additional_options = get_setting(view, "additional_options", [])
    build_dir = get_setting(view, "build_dir", "build")
    default_options = get_setting(view, "default_options", ["-std=c++11"])
    return get_options(project_path, additional_options, build_dir, default_options)

def get_unsaved_buffer(view):
    buffer = None
    if view.is_dirty():
        buffer = view.substr(sublime.Region(0, view.size()))
    return buffer

class ClangCompleteClearCache(sublime_plugin.TextCommand):
    def run(self, edit):
        global project_options
        sublime.status_message("Clearing cache...")
        project_options = {}
        free_all()

class ClangCompleteShowUsage(sublime_plugin.TextCommand):
    def run(self, edit):
        filename = self.view.file_name()
        # The view hasnt finsished loading yet
        if (filename is None): return

        usage = get_usage(filename, get_args(self.view))
        data = '\n'.join([key + ": " + str(value) for key, value in usage.items()])

        panel = self.view.window().get_output_panel("clangusage")

        panel.set_read_only(False)
        panel.set_scratch(True)
        panel.erase(edit, sublime.Region(0, panel.size()))
        panel.insert(edit, 0, data)
        panel.set_read_only(True)

        self.view.window().run_command("show_panel", {"panel": "output.clangusage"})

class ClangCompleteGotoDef(sublime_plugin.TextCommand):
    def run(self, edit):
        filename = self.view.file_name()
        # The view hasnt finsished loading yet
        if (filename is None): return

        reparse(filename, get_args(self.view), get_unsaved_buffer(self.view))

        pos = self.view.sel()[0].begin()
        row, col = self.view.rowcol(pos)
        target = get_definition(filename, get_args(self.view), row+1, col+1)

        if (len(target) is 0): sublime.status_message("Cant find definition")
        else: self.view.window().open_file(target, sublime.ENCODED_POSITION)

class ClangCompleteShowType(sublime_plugin.TextCommand):
    def run(self, edit):
        filename = self.view.file_name()
        # The view hasnt finsished loading yet
        if (filename is None): return

        reparse(filename, get_args(self.view), get_unsaved_buffer(self.view))

        pos = self.view.sel()[0].begin()
        row, col = self.view.rowcol(pos)
        type = get_type(filename, get_args(self.view), row+1, col+1)

        sublime.status_message(type)

class ClangCompleteCompletion(sublime_plugin.EventListener):
    def run(self, edit):
        print('Run completion');

    def complete_at(self, view, prefix, location):
        filename = view.file_name()
        if not is_supported_language(view):
            return []

        row, col = view.rowcol(location - len(prefix))
        completions = get_completions(filename, get_args(view), row+1, col+1, prefix, get_unsaved_buffer(view))

        return completions;

    def diagnostics(self, view):
        filename = view.file_name()
        return get_diagnostics(filename, get_args(view))

    def show_diagnostics(self, view):
        output = '\n'.join(self.diagnostics(view))
        clang_error_panel.set_data(output)
        window = view.window()
        if not window is None and len(output) > 1:
            window.run_command("clang_toggle_panel", {"show": True})

    def on_post_text_command(self, view, name, args):
        if not is_supported_language(view): return

        if 'delete' in name: return

    def on_query_completions(self, view, prefix, locations):
        if not is_supported_language(view):
            return []

        completions = self.complete_at(view, prefix, locations[0])
        if (get_setting(view, "inhibit_sublime_completions", True)):
            return (completions, sublime.INHIBIT_WORD_COMPLETIONS | sublime.INHIBIT_EXPLICIT_COMPLETIONS)
        else:
            return (completions)

    def on_post_save_async(self, view):
        if not is_supported_language(view): return

        self.show_diagnostics(view)

    def on_close(self, view):
        if is_supported_language(view):
            free_tu(view.file_name())
