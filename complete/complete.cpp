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
#include <iterator>
#include <algorithm>
#include <unordered_map>
#include <cstring>

#include "complete.h"

std::ofstream dump_log("/home/corneliu/clang_log");

namespace std {

  string& to_string(string& s)
  {
    return s;
  }

  const string& to_string(const string& s)
  {
    return s;
  }

}

typedef std::tuple<std::string, std::string> Completion;

class timer
{
  typedef typename std::conditional<std::chrono::high_resolution_clock::is_steady,
  std::chrono::high_resolution_clock,
  std::chrono::steady_clock>::type clock_type;
  typedef std::chrono::milliseconds milliseconds;
public:
  explicit timer(bool run = false)
  {
    if (run) this->reset();
  }
  void reset()
  {
    this->start = clock_type::now();
  }
  milliseconds elapsed() const
  {
    return std::chrono::duration_cast<milliseconds>(clock_type::now() - this->start);
  }
    template <typename Stream>
  friend Stream& operator<<(Stream& out, const timer& self)
  {
    return out << self.elapsed().count();
  }
private:
  clock_type::time_point start;
};

// An improved async, that doesn't block
template< class Function, class... Args>
std::future<typename std::result_of<Function(Args...)>::type>
detach_async( Function&& f, Args&&... args )
{
  typedef typename std::result_of<Function(Args...)>::type result_type;
  std::packaged_task<result_type(Args...)> task(std::forward<Function>(f));
  auto fut = task.get_future();
  std::thread(std::move(task)).detach();
  return std::move(fut);
}

inline bool starts_with(const char *str, const char *pre)
{
  size_t lenpre = strlen(pre),
  lenstr = strlen(str);
  return lenstr < lenpre ? false : strncmp(pre, str, lenpre) == 0;
}

inline bool istarts_with(const std::string& str, const std::string& pre)
{
  return str.length() < pre.length() ? false :
  std::equal(pre.begin(), pre.end(), str.begin(), [](char a, char b) { return std::tolower(a) == std::tolower(b); });
}

std::string get_line_at(const std::string& str, unsigned int line)
{
  int n = 1;
  std::string::size_type pos = 0;
  std::string::size_type prev = 0;
  while ((pos = str.find('\n', prev)) != std::string::npos)
  {
    if (n == line) return str.substr(prev, pos - prev);
    prev = pos + 1;
    n++;
  }

    // To get the last line
  if (n == line) return str.substr(prev);
  else return "";
}

CXIndex get_index()
{
  static std::shared_ptr<void> index = std::shared_ptr<void>(clang_createIndex(1, 1), &clang_disposeIndex);
  return index.get();
}

class translation_unit
{
    // CXIndex index;
  CXTranslationUnit tu;
  const std::string filename;
  std::timed_mutex m;

  CXUnsavedFile unsaved_buffer(const char * buffer, unsigned len)
  {
    CXUnsavedFile result;
    result.Filename = this->filename.c_str();
    result.Contents = buffer;
    result.Length = len;
    return result;
  }

  static std::string to_std_string(CXString str)
  {
    std::string result;
    const char * s = clang_getCString(str);
    if (s != nullptr) result = s;
    clang_disposeString(str);
    return result;
  }

  struct completion_results
  {
    std::shared_ptr<CXCodeCompleteResults> results;
    typedef CXCompletionResult* iterator;

    completion_results(CXCodeCompleteResults* r)
    {
      this->results = std::shared_ptr<CXCodeCompleteResults>(r, &clang_disposeCodeCompleteResults);
      if (results)
        dump_log << "Num results: " << results->NumResults << std::endl;
      else
        dump_log << "No results" << std::endl;
    }

    iterator begin()
    {
      if (results == nullptr) return nullptr;
      else return results->Results;
    }

    iterator end()
    {
      if (results == nullptr) return nullptr;
      else return results->Results + results->NumResults;
    }
  };

    template<class F>
  static void for_each_completion_string(const CXCompletionString& c, F f)
  {
    if (clang_getCompletionAvailability(c) == CXAvailability_Available )
    {
      int num = clang_getNumCompletionChunks(c);
      for(int i=0;i<num;i++)
      {
        auto kind = clang_getCompletionChunkKind(c, i);
        if (kind == CXCompletionChunk_Optional) {
          for_each_completion_string(clang_getCompletionChunkCompletionString(c, i), f);
        }
        else {
          auto str = clang_getCompletionChunkText(c, i);
          f(to_std_string(str), kind);
        }
      }
    }
  }

  static std::string get_typed_text(CXCompletionResult& c)
  {
    if ( clang_getCompletionAvailability( c.CompletionString ) == CXAvailability_Available )
    {
      int num = clang_getNumCompletionChunks(c.CompletionString);
      for(int i=0;i<num;i++)
      {
        auto str = clang_getCompletionChunkText(c.CompletionString, i);
        auto kind = clang_getCompletionChunkKind(c.CompletionString, i);
        if (kind == CXCompletionChunk_TypedText) return to_std_string(str);
      }
    }
    return {};
  }

  completion_results completions_at(unsigned line, unsigned col, const char * buffer, unsigned len)
  {
    if (buffer == nullptr)
    {
      return clang_codeCompleteAt(this->tu, this->filename.c_str(), line, col, nullptr, 0, 0);
    }
    else
    {
      auto unsaved = this->unsaved_buffer(buffer, len);
      return clang_codeCompleteAt(this->tu, this->filename.c_str(), line, col, &unsaved, 1, 0);
    }
  }

  void unsafe_reparse(const char * buffer=nullptr, unsigned len=0)
  {
    if (buffer == nullptr) clang_reparseTranslationUnit(this->tu, 0, nullptr, clang_defaultReparseOptions(this->tu));
    else
    {
      auto unsaved = this->unsaved_buffer(buffer, len);
      clang_reparseTranslationUnit(this->tu, 1, &unsaved, clang_defaultReparseOptions(this->tu));
    }
  }
public:
  struct cursor
  {
    CXCursor c;

    cursor(CXCursor c) : c(c)
    {}

    CXCursorKind get_kind()
    {
      return clang_getCursorKind(this->c);
    }

    cursor get_reference()
    {
      return cursor(clang_getCursorReferenced(this->c));
    }

    cursor get_definition()
    {
      return cursor(clang_getCursorDefinition(this->c));
    }

    cursor get_type()
    {
      return cursor(clang_getTypeDeclaration(clang_getCanonicalType(clang_getCursorType(this->c))));
    }

    std::string get_display_name()
    {
      return to_std_string(clang_getCursorDisplayName(this->c));
    }

    std::string get_spelling()
    {
      return to_std_string(clang_getCursorSpelling(this->c));
    }

    std::string get_type_name()
    {
      //return to_std_string(clang_getTypeSpelling(clang_getCanonicalType(clang_getCursorType(this->c))));
      auto res = to_std_string(clang_getTypeSpelling(clang_getCanonicalType(clang_getCursorType(this->c))));
      dump_log << "Type: " << res << std::endl;
      return res;
    }

    CXSourceLocation get_location()
    {
      return clang_getCursorLocation(this->c);
    }

    std::string get_location_path()
    {
      CXFile f;
      unsigned line, col, offset;
      clang_getSpellingLocation(this->get_location(), &f, &line, &col, &offset);
      return to_std_string(clang_getFileName(f)) + ":" + std::to_string(line) + ":" + std::to_string(col);
    }

    std::string get_include_file()
    {
      CXFile f = clang_getIncludedFile(this->c);
      return to_std_string(clang_getFileName(f));
    }

    bool is_null()
    {
      return clang_Cursor_isNull(this->c);
    }
  };
  translation_unit(const char * filename, const char ** args, int argv) : filename(filename)
  {
        // this->index = clang_createIndex(1, 1);
    dump_log << "Parsing translation unit:" << filename << std::endl;
    std::vector<std::string> vals(args, args + argv);
    for (auto& v: vals)
      dump_log << v << " ";
    dump_log << std::endl;
    this->tu = clang_parseTranslationUnit(get_index(), filename, args, argv, NULL, 0, clang_defaultEditingTranslationUnitOptions());
    detach_async([=]() { this->reparse(); });
  }

  translation_unit(const translation_unit&) = delete;

  cursor get_cursor_at(unsigned long line, unsigned long col, const char * name=nullptr)
  {
    if (name == nullptr) name = this->filename.c_str();
    dump_log << "Get cursor at:" << name << ":" << line << ":" << col << std::endl;
    CXFile f = clang_getFile(this->tu, name);
    CXSourceLocation loc = clang_getLocation(this->tu, f, line, col);
    return cursor(clang_getCursor(this->tu, loc));
  }

  void reparse(const char * buffer=nullptr, unsigned len=0)
  {
    std::lock_guard<std::timed_mutex> lock(this->m);
    this->unsafe_reparse(buffer, len);
  }

  struct usage
  {
    CXTUResourceUsage u;

    typedef CXTUResourceUsageEntry* iterator;

    usage(CXTUResourceUsage u) : u(u)
    {}

    usage(const usage&) = delete;


    iterator begin()
    {
      return u.entries;
    }

    iterator end()
    {
      return u.entries + u.numEntries;
    }

    ~usage()
    {
      clang_disposeCXTUResourceUsage(u);
    }
  };

  std::unordered_map<std::string, unsigned long> get_usage()
  {
    std::lock_guard<std::timed_mutex> lock(this->m);
    std::unordered_map<std::string, unsigned long> result;
    auto u = std::make_shared<usage>(clang_getCXTUResourceUsage(this->tu));
    for(CXTUResourceUsageEntry e:*u)
    {
      result.insert(std::make_pair(clang_getTUResourceUsageName(e.kind), e.amount));
    }
    return result;

  }

  std::set<Completion> complete_at(unsigned line, unsigned col, const char * prefix, const char * buffer=nullptr, unsigned len=0)
  {
    std::lock_guard<std::timed_mutex> lock(this->m);
    std::set<Completion> results;
    for(auto& c:this->completions_at(line, col, buffer, len))
    {
      std::stringstream display;
      std::stringstream replacement;

      std::size_t idx = 1;
      for_each_completion_string(c.CompletionString, [&](std::string&& text, CXCompletionChunkKind kind) {
        switch(kind) {
          case CXCompletionChunk_LeftParen:
          case CXCompletionChunk_RightParen:
          case CXCompletionChunk_LeftBracket:
          case CXCompletionChunk_RightBracket:
          case CXCompletionChunk_LeftBrace:
          case CXCompletionChunk_RightBrace:
          case CXCompletionChunk_LeftAngle:
          case CXCompletionChunk_RightAngle:
          case CXCompletionChunk_TypedText:
          case CXCompletionChunk_CurrentParameter:
          case CXCompletionChunk_Colon:
          case CXCompletionChunk_Comma:
          case CXCompletionChunk_HorizontalSpace:
          case CXCompletionChunk_VerticalSpace:
            display << text;
            replacement << text;
            break;
          case CXCompletionChunk_Placeholder:
            display << text;
            replacement << "${" << idx++ << ":" << text << "}";
            break;
          case CXCompletionChunk_ResultType:
          case CXCompletionChunk_Text:
            display << text << " ";
            break;
          default:
            dump_log << "Kind:" << kind << " Text:" << text << std::endl;
        }
      });
      dump_log << "display:" << display.str() << "\nreplacement:" << replacement.str() << std::endl;
      results.insert(std::make_tuple(display.str(), replacement.str()));
      //if (!text.empty() and starts_with(text.c_str(), prefix)) results.insert(text);
    }
    dump_log << std::endl;
        // Perhaps a reparse can help rejuvenate clang?
    if (results.size() == 0) this->unsafe_reparse(buffer, len);
        // if (buffer != nullptr) dump_log << get_line_at(std::string(buffer, len), line) << std::endl;
    return results;
  }

  std::vector<std::string> get_diagnostics(int timeout=-1)
  {
    std::unique_lock<std::timed_mutex> lock(this->m, std::defer_lock);
    if (timeout < 0)
    {
      lock.lock();
    }
    else
    {
      if (!lock.try_lock_for(std::chrono::milliseconds(timeout))) return {};
    }
    std::vector<std::string> result;
    auto n = clang_getNumDiagnostics(this->tu);
    for(int i=0;i<n;i++)
    {
      auto diag = std::shared_ptr<void>(clang_getDiagnostic(this->tu, i), &clang_disposeDiagnostic);
      if (diag != nullptr and clang_getDiagnosticSeverity(diag.get()) != CXDiagnostic_Ignored)
      {
        auto str = clang_formatDiagnostic(diag.get(), clang_defaultDiagnosticDisplayOptions());
        result.push_back(to_std_string(str));
      }
    }
    return result;
  }

  std::string get_definition(unsigned line, unsigned col) {
    std::lock_guard<std::timed_mutex> lock(this->m);
    std::string result;
    cursor c = this->get_cursor_at(line, col);
    cursor ref = c.get_reference();
    if (!ref.is_null())
    {
      result = ref.get_location_path();
    }
    else if (c.get_kind() == CXCursor_InclusionDirective)
    {
      result = c.get_include_file();
    }
    return result;
  }

  std::string get_type(unsigned line, unsigned col)
  {
    std::lock_guard<std::timed_mutex> lock(this->m);
    return this->get_cursor_at(line, col).get_type_name();
  }

  ~translation_unit()
  {
    std::lock_guard<std::timed_mutex> lock(this->m);
    clang_disposeTranslationUnit(this->tu);
  }
};

#ifndef CLANG_COMPLETE_ASYNC_WAIT_MS
#define CLANG_COMPLETE_ASYNC_WAIT_MS 500
#endif

class async_translation_unit : public translation_unit
{

  struct query
  {
    std::future<std::set<Completion>> results_future;
    std::set<Completion> results;
    unsigned line;
    unsigned col;

    query() : line(0), col(0)
    {}

    std::pair<unsigned, unsigned> get_loc()
    {
      return std::make_pair(this->line, this->col);
    }

    void set(std::future<std::set<Completion>> && results_future, unsigned line, unsigned col)
    {
      this->results = {};
      this->results_future = std::move(results_future);
      this->line = line;
      this->col = col;
    }

    std::set<Completion> get(int timeout)
    {
      if (results_future.valid() and this->ready(timeout))
      {
        this->results = this->results_future.get();
        // Force another query if completion results are empty
        if (this->results.size() == 0) std::tie(line, col) = std::make_pair(0, 0);
      }
      return this->results;
    }

    bool ready(int timeout = 10)
    {
      if (results_future.valid()) return (timeout > 0 and results_future.wait_for(std::chrono::milliseconds(timeout)) == std::future_status::ready);
      else return true;
    }

  };
  std::timed_mutex async_mutex;
  query q;

public:
  async_translation_unit(const char * filename, const char ** args, int argv) : translation_unit(filename, args, argv)
  {}


  std::set<Completion> async_complete_at(unsigned line, unsigned col, const char * prefix, int timeout, const char * buffer=nullptr, unsigned len=0)
  {
    std::unique_lock<std::timed_mutex> lock(this->async_mutex, std::defer_lock);
    if (!lock.try_lock_for(std::chrono::milliseconds(20))) return {};

    if (std::make_pair(line, col) != q.get_loc())
    {
            // If we are busy with a query, lets avoid making lots of new queries
      if (not this->q.ready()) return {};

      std::string buffer_as_string(buffer, buffer+len);
      this->q.set(detach_async([=]
      {
        auto b = buffer_as_string.c_str();
        if (buffer == nullptr) b = nullptr;
                // TODO: Should we always reparse?
                // else this->reparse(b, len);
        return this->complete_at(line, col, "", b, buffer_as_string.length());
      }), line, col);
    }
    auto completions = q.get(timeout);
    std::set<Completion> results;
    std::string pre = prefix;
    std::copy_if(completions.begin(), completions.end(), inserter(results, results.begin()), [&](const std::tuple<std::string, std::string>& x)
    {
      return istarts_with(std::get<0>(x), pre);
    });
    return results;
  }
};

#ifndef CLANG_COMPLETE_MAX_RESULTS
#define CLANG_COMPLETE_MAX_RESULTS 8192
#endif

std::timed_mutex tus_mutex;
std::unordered_map<std::string, std::shared_ptr<async_translation_unit>> tus;

std::shared_ptr<async_translation_unit> get_tu(const char * filename, const char ** args, int argv)
{
  std::lock_guard<std::timed_mutex> lock(tus_mutex);
  if (tus.find(filename) == tus.end())
  {
    tus[filename] = std::make_shared<async_translation_unit>(filename, args, argv);
  }
  return tus[filename];
}

template<class Range>
PyObject* export_pylist(const Range& r)
{
  PyObject* result = PyList_New(0);

  for (const auto& s:r)
  {
    PyList_Append(result, PyUnicode_FromString(s.c_str()));
  }

  return result;
}

template<class Range>
PyObject* export_tuple_pylist(const Range& r)
{
  PyObject* result = PyList_New(0);

  for (const auto& s:r)
  {
    PyList_Append(result, PyTuple_Pack(2, PyUnicode_FromString(std::get<0>(s).c_str()), PyUnicode_FromString(std::get<1>(s).c_str())));
  }

  return result;
}

template<class Range>
PyObject* export_pydict_string_ulong(const Range& r)
{
  PyObject* result = PyDict_New();

  for (const auto& p:r)
  {
    PyDict_SetItem(result, PyUnicode_FromString(p.first.c_str()), PyLong_FromUnsignedLong(p.second));
  }

  return result;
}


extern "C" {
  PyObject* clang_complete_get_completions(
    const char * filename,
    const char ** args,
    int argv,
    unsigned line,
    unsigned col,
    const char * prefix,
    int timeout,
    const char * buffer,
    unsigned len)
  {
    auto tu = get_tu(filename, args, argv);
    dump_log << "prefix: " << prefix << std::endl;
    return export_tuple_pylist(tu->async_complete_at(line, col, prefix, timeout, buffer, len));
  }

  PyObject* clang_complete_get_diagnostics(const char * filename, const char ** args, int argv)
  {
    auto tu = get_tu(filename, args, argv);
    tu->reparse(nullptr, 0);

    return export_pylist(tu->get_diagnostics(250));
  }

  PyObject* clang_complete_get_usage(const char * filename, const char ** args, int argv)
  {
    auto tu = get_tu(filename, args, argv);

    return export_pydict_string_ulong(tu->get_usage());
  }

  PyObject* clang_complete_get_definition(const char * filename, const char ** args, int argv, unsigned line, unsigned col)
  {
    auto tu = get_tu(filename, args, argv);

    return PyUnicode_FromString(tu->get_definition(line, col).c_str());
  }

  PyObject* clang_complete_get_type(const char * filename, const char ** args, int argv, unsigned line, unsigned col)
  {
    auto tu = get_tu(filename, args, argv);

    return PyUnicode_FromString(tu->get_type(line, col).c_str());
  }

  void clang_complete_reparse(const char * filename, const char ** args, int argv, const char * buffer, unsigned len)
  {
    auto tu = get_tu(filename, args, argv);
    tu->reparse();
  }

  void clang_complete_free_tu(const char * filename)
  {
    std::lock_guard<std::timed_mutex> lock(tus_mutex);
    if (tus.find(filename) != tus.end())
    {
      tus.erase(filename);
    }
  }

  void clang_complete_free_all()
  {
    std::lock_guard<std::timed_mutex> lock(tus_mutex);
    tus.clear();
  }
}


#endif
