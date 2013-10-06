#ifndef CLANG_UTILS_TRANSLATION_UNIT_H
#define CLANG_UTILS_TRANSLATION_UNIT_H

#include <python3.3/Python.h>
#include <clang-c/Index.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <memory>
#include <future>
#include <mutex>
#include <thread>
#include <list>
#include <iterator>
#include <algorithm>
#include <unordered_map>
#include <cstring>
#include <stack>

#include "complete.h"

std::ofstream logger("/home/corneliu/clang_log");

typedef std::tuple<std::size_t, std::string, std::string> Completion;

struct timer {
  typedef std::chrono::seconds s;
  typedef std::chrono::microseconds us;

  timer() : start_time(now()) {}

  std::chrono::time_point<std::chrono::system_clock> now() { return std::chrono::system_clock::now(); }

  void start() { start_time = now(); }

  void stop() { stop_time = now(); }

  std::size_t count() { return std::chrono::duration_cast<us>(stop_time - start_time).count(); }

  double seconds() { return count() / 1000000.0; }

  std::chrono::time_point<std::chrono::system_clock> start_time;
  std::chrono::time_point<std::chrono::system_clock> stop_time;
};

struct processor {
  processor()
    : _thread([this] { this->run(); }) {}

  template <typename ReturnType> std::future<ReturnType> execute(std::function<ReturnType()>& f) {
    auto promise = std::make_shared<std::promise<ReturnType>>();
    _tasks.emplace_back([=] { promise->set_value(f()); });
    return promise->get_future();
  }

  void run() {
    while (true) {
      if (_tasks.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        continue;
      }

      auto next = std::move(_tasks.front());
      _tasks.pop_front();
      next();
    }
  }

  std::thread _thread;
  std::list<std::function<void()>> _tasks;
};

inline bool istarts_with(const std::string& str, const std::string& pre) {
  return str.length() < pre.length() ? false : std::equal(pre.begin(), pre.end(), str.begin(), [](char a, char b) {
                                                 return std::tolower(a) == std::tolower(b);
                                               });
}

std::string get_line_at(const std::string& str, unsigned int line) {
  int n = 1;
  std::string::size_type pos = 0;
  std::string::size_type prev = 0;
  while ((pos = str.find('\n', prev)) != std::string::npos) {
    if (n == line) return str.substr(prev, pos - prev);
    prev = pos + 1;
    n++;
  }

  // To get the last line
  if (n == line)
    return str.substr(prev);
  else
    return "";
}

CXIndex get_index() {
  static std::shared_ptr<void> index = std::shared_ptr<void>(clang_createIndex(1, 1), &clang_disposeIndex);
  return index.get();
}

class translation_unit {
  CXTranslationUnit _tu;
  const std::string _filename;

  CXUnsavedFile unsaved_buffer(const std::string& buffer, unsigned len) {
    CXUnsavedFile result;
    result.Filename = _filename.c_str();
    result.Contents = buffer.c_str();
    result.Length = len;
    return result;
  }

  static std::string to_std_string(CXString str) {
    std::string result;
    const char* s = clang_getCString(str);
    if (s != nullptr) result = s;
    clang_disposeString(str);
    return result;
  }

  struct completion_results {
    std::shared_ptr<CXCodeCompleteResults> _results;
    typedef CXCompletionResult* iterator;

    completion_results(CXCodeCompleteResults* r) {
      _results = std::shared_ptr<CXCodeCompleteResults>(r, &clang_disposeCodeCompleteResults);
    }

    iterator begin() { return _results ? _results->Results : nullptr; }

    iterator end() { return _results ? _results->Results + _results->NumResults : nullptr; }
  };

  template <class F> static void for_each_completion_string(const CXCompletionString& c, const CXCursorKind k, F func) {
    if (clang_getCompletionAvailability(c) == CXAvailability_Available) {
      int num = clang_getNumCompletionChunks(c);
      for (int i = 0; i < num; ++i) {
        auto kind = clang_getCompletionChunkKind(c, i);
        if (kind == CXCompletionChunk_Optional) {
          for_each_completion_string(clang_getCompletionChunkCompletionString(c, i), k, func);
        } else {
          auto str = to_std_string(clang_getCompletionChunkText(c, i));
          func(std::move(str), k, kind);
        }
      }
    }
  }

  template <class F> static void for_each_completion_result(const CXCompletionResult& completion, F func) {
    const auto c = completion.CompletionString;
    const auto k = completion.CursorKind;
    for_each_completion_string(c, k, func);
  }

  completion_results completions_at(unsigned line, unsigned col, const std::string& buffer, unsigned len) {
    if (buffer.empty()) {
      return clang_codeCompleteAt(_tu, _filename.c_str(), line, col, nullptr, 0, 0);
    } else {
      auto unsaved = this->unsaved_buffer(buffer, len);
      return clang_codeCompleteAt(_tu, _filename.c_str(), line, col, &unsaved, 1, 0);
    }
  }

public:
  void reparse(const std::string& buffer = "", unsigned len = 0) {
    if (buffer.empty())
      clang_reparseTranslationUnit(_tu, 0, nullptr, clang_defaultReparseOptions(_tu));
    else {
      auto unsaved = this->unsaved_buffer(buffer, len);
      clang_reparseTranslationUnit(_tu, 1, &unsaved, clang_defaultReparseOptions(_tu));
    }
  }

  struct cursor {
    CXCursor c;

    cursor(CXCursor c) : c(c) {}

    CXCursorKind get_kind() { return clang_getCursorKind(this->c); }

    cursor get_reference() { return cursor(clang_getCursorReferenced(this->c)); }

    cursor get_definition() { return cursor(clang_getCursorDefinition(this->c)); }

    cursor get_type() { return cursor(clang_getTypeDeclaration(clang_getCanonicalType(clang_getCursorType(this->c)))); }

    std::string get_display_name() { return to_std_string(clang_getCursorDisplayName(this->c)); }

    std::string get_spelling() { return to_std_string(clang_getCursorSpelling(this->c)); }

    std::string get_type_name() {
      return to_std_string(clang_getTypeSpelling(clang_getCanonicalType(clang_getCursorType(this->c))));
    }

    CXSourceLocation get_location() { return clang_getCursorLocation(this->c); }

    std::string get_location_path() {
      CXFile f;
      unsigned line, col, offset;
      clang_getSpellingLocation(this->get_location(), &f, &line, &col, &offset);
      return to_std_string(clang_getFileName(f)) + ":" + std::to_string(line) + ":" + std::to_string(col);
    }

    std::string get_include_file() {
      CXFile f = clang_getIncludedFile(this->c);
      return to_std_string(clang_getFileName(f));
    }

    bool is_null() { return clang_Cursor_isNull(this->c); }
  };

  translation_unit(const std::string& filename, const char** args, int argv) : _filename(filename) {
    timer t;
    _tu = clang_parseTranslationUnit(get_index(), filename.c_str(), args, argv, nullptr, 0,
                                     clang_defaultEditingTranslationUnitOptions());
    t.stop();
    logger << "Parsed translation unit:" << filename << " in " << t.seconds() << std::endl;
  }

  translation_unit(const translation_unit&) = delete;

  cursor get_cursor_at(unsigned long line, unsigned long col) {
    CXFile f = clang_getFile(_tu, _filename.c_str());
    CXSourceLocation loc = clang_getLocation(_tu, f, line, col);
    return cursor(clang_getCursor(_tu, loc));
  }

  struct usage {
    CXTUResourceUsage u;

    typedef CXTUResourceUsageEntry* iterator;

    usage(CXTUResourceUsage u) : u(u) {}

    usage(const usage&) = delete;

    iterator begin() { return u.entries; }

    iterator end() { return u.entries + u.numEntries; }

    ~usage() { clang_disposeCXTUResourceUsage(u); }
  };

  std::unordered_map<std::string, unsigned long> get_usage() {
    std::unordered_map<std::string, unsigned long> result;
    auto u = std::make_shared<usage>(clang_getCXTUResourceUsage(_tu));
    for (CXTUResourceUsageEntry e : *u) {
      result.insert(std::make_pair(clang_getTUResourceUsageName(e.kind), e.amount));
    }
    return result;
  }

  std::set<Completion> complete_at(unsigned line, unsigned col, const std::string& prefix, const std::string& buffer,
                                   unsigned len) {
    this->reparse(buffer, len);

    std::set<Completion> results;
    for (auto& c : this->completions_at(line, col, buffer, len)) {
      auto priority = clang_getCompletionPriority(c.CompletionString);

      std::stringstream display;
      std::stringstream replacement;

      std::size_t idx = 1;
      bool matches = true;
      for_each_completion_result(c, [&](std::string && text, CXCursorKind ck, CXCompletionChunkKind kind) {
        if (ck == CXCursor_MacroExpansion)
          return;

        switch (kind) {
          case CXCompletionChunk_LeftParen:
          case CXCompletionChunk_RightParen:
          case CXCompletionChunk_LeftBracket:
          case CXCompletionChunk_RightBracket:
          case CXCompletionChunk_LeftBrace:
          case CXCompletionChunk_RightBrace:
          case CXCompletionChunk_LeftAngle:
          case CXCompletionChunk_RightAngle:
          case CXCompletionChunk_CurrentParameter:
          case CXCompletionChunk_Colon:
          case CXCompletionChunk_Comma:
          case CXCompletionChunk_HorizontalSpace:
          case CXCompletionChunk_VerticalSpace:
            display << text;
            replacement << text;
            break;
          case CXCompletionChunk_TypedText:
            matches = istarts_with(text, prefix);
            display << text;
            replacement << text;
            if (ck == CXCursor_Constructor)
              replacement << " ${" << idx++ << ":v}";
            break;
          case CXCompletionChunk_Placeholder:
            display << text;
            replacement << "${" << idx++ << ":" << text << "}";
            break;
          case CXCompletionChunk_ResultType:
          case CXCompletionChunk_Text:
          case CXCompletionChunk_Informative:
          case CXCompletionChunk_Equal:
            display << text << " ";
            break;
          default:
            logger << "Kind:" << kind << " Text:" << text << std::endl;
        }
      });

      if (!matches) continue;

      auto resp = std::make_tuple(priority, display.str(), replacement.str());
      if (!std::get<1>(resp).empty() && !std::get<2>(resp).empty()) results.insert(resp);
    }

    return results;
  }

  void process_diagnostic_set(CXDiagnosticSet set, std::vector<std::string>& results, std::size_t depth = 0) {
    const std::size_t indent_size = 2;
    if (!set) return;

    auto num_diagnostics = clang_getNumDiagnosticsInSet(set);
    for (auto i = 0; i < num_diagnostics; ++i) {
      auto diag = clang_getDiagnosticInSet(set, i);
      if (!diag) continue;

      if (clang_getDiagnosticSeverity(diag) != CXDiagnostic_Ignored) {
        std::stringstream formatter;
        for (auto i = 0; i < depth; ++i)
          for (auto j = 0; j < indent_size; ++j) formatter << " ";

        formatter << to_std_string(clang_formatDiagnostic(diag, clang_defaultDiagnosticDisplayOptions()));
        results.push_back(formatter.str());

        auto child = clang_getChildDiagnostics(diag);
        if (child) process_diagnostic_set(child, results, depth + 1);
      }
      clang_disposeDiagnostic(diag);
    }
  }

  std::vector<std::string> get_diagnostics() {
    std::vector<std::string> result;
    auto set = clang_getDiagnosticSetFromTU(_tu);
    process_diagnostic_set(set, result);
    clang_disposeDiagnosticSet(set);

    return result;
  }

  std::string get_definition(unsigned line, unsigned col) {
    std::string result;
    cursor c = this->get_cursor_at(line, col);
    cursor def = c.get_definition();
    if (!def.is_null()) {
      result = def.get_location_path();
    } else if (c.get_kind() == CXCursor_InclusionDirective) {
      result = c.get_include_file();
    }
    return result;
  }

  std::string get_type(unsigned line, unsigned col) { return this->get_cursor_at(line, col).get_type_name(); }

  ~translation_unit() { clang_disposeTranslationUnit(_tu); }
};

std::unordered_map<std::string, std::shared_ptr<translation_unit>> tus;

std::shared_ptr<translation_unit> get_tu(const std::string& filename, const char** args, int argv) {
  auto& tu = tus[filename];
  if (!tu) tu = std::make_shared<translation_unit>(filename, args, argv);
  return tu;
}

template <class Range> PyObject* export_pylist(const Range& r) {
  PyObject* result = PyList_New(0);

  for (const auto& s : r) {
    PyList_Append(result, PyUnicode_FromString(s.c_str()));
  }

  return result;
}

template <class Range> PyObject* export_tuple_pylist(const Range& r) {
  PyObject* result = PyList_New(0);

  for (const auto& s : r) {
    PyList_Append(result, PyTuple_Pack(2, PyUnicode_FromString(std::get<1>(s).c_str()),
                                       PyUnicode_FromString(std::get<2>(s).c_str())));
  }

  return result;
}

template <class Range> PyObject* export_pydict_string_ulong(const Range& r) {
  PyObject* result = PyDict_New();

  for (const auto& p : r) {
    PyDict_SetItem(result, PyUnicode_FromString(p.first.c_str()), PyLong_FromUnsignedLong(p.second));
  }

  return result;
}

std::mutex _lock;

PyObject* default_list = PyList_New(0);
PyObject* default_dict = PyDict_New();
PyObject* default_str = PyUnicode_FromString("");

processor p;
extern "C" {

PyObject* clang_complete_get_completions(const char* filename, const char** args, int argv, unsigned line, unsigned col,
                                         const char* prefix_, const char* buffer_, unsigned len) {
  static std::set<Completion> cached;
  static std::size_t _line = 0;
  static std::size_t _col = 0;

  if (line == _line && col == _col) {
    std::lock_guard<std::mutex> g(_lock);
    return export_tuple_pylist(cached);
  }

  logger << "get_completions for " << line << ":" << col << std::endl;

  auto tu = get_tu(filename, args, argv);
  auto prefix = std::make_shared<std::string>(prefix_);
  auto buffer = std::make_shared<std::string>(buffer_);

  std::function<PyObject*()> f = [=] {
    {
      std::lock_guard<std::mutex> g(_lock);
      cached = tu->complete_at(line, col, *prefix, *buffer, len);
      _line = line;
      _col = col;
    }

    logger << "completion for " << line << ":" << col << " is ready" << std::endl;
    return export_tuple_pylist(cached);
  };

  auto fut = p.execute(f);
  if (fut.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready) return fut.get();
  logger << "timeout" << std::endl;
  return PyList_New(0);
}

PyObject* clang_complete_get_diagnostics(const char* filename, const char** args, int argv) {
  logger << "get_diagnostics" << std::endl;

  auto tu = get_tu(filename, args, argv);

  std::function<PyObject*()> f = [=] {
    tu->reparse();
    auto res = tu->get_diagnostics();
    return export_pylist(res);
  };

  auto fut = p.execute(f);
  if (fut.wait_for(std::chrono::milliseconds(1000)) == std::future_status::ready) return fut.get();
  logger << "timeout" << std::endl;
  return PyList_New(0);
}

PyObject* clang_complete_get_usage(const char* filename, const char** args, int argv) {
  logger << "get_usage" << std::endl;

  auto tu = get_tu(filename, args, argv);
  std::function<PyObject*()> f = [=] {
    auto usage = tu->get_usage();
    return export_pydict_string_ulong(usage);
  };

  auto fut = p.execute(f);
  if (fut.wait_for(std::chrono::milliseconds(100)) == std::future_status::ready) return fut.get();
  logger << "timeout" << std::endl;
  return PyDict_New();
}

PyObject* clang_complete_get_definition(const char* filename, const char** args, int argv, unsigned line,
                                        unsigned col) {
  logger << "get_definition" << std::endl;

  auto tu = get_tu(filename, args, argv);
  return PyUnicode_FromString(tu->get_definition(line, col).c_str());
}

PyObject* clang_complete_get_type(const char* filename, const char** args, int argv, unsigned line, unsigned col) {
  logger << "get_type" << std::endl;

  auto tu = get_tu(filename, args, argv);
  return PyUnicode_FromString(tu->get_type(line, col).c_str());
}

void clang_complete_reparse(const char* filename, const char** args, int argv, const char* buffer, unsigned len) {
  logger << "reparse" << std::endl;

  auto tu = get_tu(filename, args, argv);
  tu->reparse();
}

void clang_complete_free_tu(const char* filename) {
  logger << "free_tu" << std::endl;

  if (tus.find(filename) != tus.end()) {
    tus.erase(filename);
  }
}

void clang_complete_free_all() {
  logger << "free_all" << std::endl;
  tus.clear();
}
}

#endif
