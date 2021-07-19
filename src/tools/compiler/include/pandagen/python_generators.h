/* SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020,2021 SiPanda Inc.
 *
 * Authors: Felipe Magno de Almeida <felipe@expertise.dev>
 *          João Paulo Taylor Ienczak Zanette <joao.tiz@expertise.dev>
 *          Lucas Cavalcante de Sousa <lucas@expertise.dev>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef PANDAGEN_PYTHON_GENERATORS_H
#define PANDAGEN_PYTHON_GENERATORS_H

#include <vector>

#include <Python.h>

extern const char* pyratempsrc;
extern const char* template_gen;
extern const char* user_xdp_common_template_str;
extern const char* c_def_template_str;
extern const char *kmod_def_template_str;
extern const char* xdp_def_template_str;

namespace pandagen::python {

template <typename T>
auto ensure_not_null(T* t, std::string const& msg) {
  if (t == NULL) {
    throw std::runtime_error(msg);
  }

  return t;
}

void decref(PyObject* obj) {
  Py_DECREF(obj);
}

using python_object_deleter_t = std::function<decltype(decref)>;
using python_object_t = std::unique_ptr<PyObject, python_object_deleter_t>;

auto make_python_object(PyObject* obj) {
  return python_object_t{obj, decref};
}

auto make_python_object(int value) {
  return make_python_object(PyLong_FromLong(value));
}

auto make_python_object(long value) {
  return make_python_object(PyLong_FromLong(value));
}

auto make_python_object(bool value) {
  return make_python_object(PyBool_FromLong(static_cast<long>(value)));
}

auto make_python_object(char const* str) {
  return make_python_object(PyUnicode_FromString(str));
}

auto make_python_object(std::string str) {
  return make_python_object(str.c_str());
}

template <typename T>
void push_back_python_object(std::vector<python_object_t>& v, T value) {
  v.push_back(make_python_object(value));
}

void push_back_python_object(std::vector<python_object_t>& v, python_object_t value) {
  v.push_back(std::move(value));
}

template <typename ...T>
auto make_python_object_vector(T... raw_values) {
  auto v = std::vector<python_object_t>{};
  ((push_back_python_object(v, std::forward<T>(raw_values))), ...);
  return v;
}

/**
 * Wrapper for python's tuple data type.
 */
struct tuple {
  template <typename ...T>
  tuple(T... raw_values)
  {
    auto values = make_python_object_vector(std::forward<T>(raw_values)...);
    auto length = values.size();
    auto py_tuple = PyTuple_New(length);
    auto i = 0;
    for (auto&& py_value: values) {
      PyTuple_SetItem(py_tuple, i, py_value.release());
      ++i;
    }
    tuple_obj = make_python_object(py_tuple);
  }

  tuple(tuple const&) = default;
  tuple(tuple&&) = default;

  auto get() const {
    return tuple_obj.get();
  }

  python_object_t tuple_obj;
};

auto make_python_object(tuple&& py_tuple) {
  return make_python_object(py_tuple.tuple_obj.release());
}

/**
 * Wrapper for python's list data type.
 */
struct list {
  template <typename ...T>
  list(T... raw_values)
  {
    auto py_list = PyList_New(sizeof...(raw_values), std::forward<T>(raw_values)...);
    list_obj = make_python_object(py_list);
  }

  list(list const&) = default;
  list(list&&) = default;

  auto get() const {
    return list_obj.get();
  }

  template <typename Value>
  auto set(ssize_t i, Value v) {
    auto py_v = make_python_object(v);
    auto success = static_cast<bool>(
      PyList_SetItem(list_obj.get(), i, py_v.release())
    );
    return success;
  }

  template <typename Value>
  auto append(Value v) {
	  auto py_v = make_python_object(std::move(v));
	  auto success = static_cast<bool>(PyList_Append(list_obj.get(), py_v.release()));
	  return success;
  }

  python_object_t list_obj;
};

auto make_python_object(list&& py_list) {
  return make_python_object(py_list.list_obj.release());
}

/**
 * Wrapper for python's dict data type.
 *
 * For simplicity, it accepts only bools, strings and integers as key.
 */
struct dict {
  dict():
    py_dict{make_python_object(PyDict_New())}
  {}

  auto operator[](python_object_t py_key) const {
    auto py_value = make_python_object(PyDict_GetItem(py_dict.get(), py_key.get()));
    return ensure_not_null(py_value.get(), "Dict object doesn't have the specified key.");
  }

  template <typename V>
  auto set(std::string const& key, V value) {
    auto py_key = make_python_object(key);
    auto py_value = make_python_object(std::move(value));
    auto success = static_cast<bool>(
      PyDict_SetItem(py_dict.get(), py_key.get(), py_value.release())
    );
    return success;
  }

  auto get() const {
    return py_dict.get();
  }

  python_object_t py_dict;
};

auto make_python_object(dict py_dict) {
  return make_python_object(py_dict.py_dict.release());
}

auto make_edge_list(graph_t const& graph, vertex_descriptor_t const& v) {
	auto targets = python::dict{};

	auto oedges = out_edges(v, graph);
	auto adjacents = boost::adjacent_vertices(v, graph);
	for (auto&& a : boost::make_iterator_range(adjacents.first, adjacents.second)) {
		python::list l;
		for (auto&& e : boost::make_iterator_range(oedges.first, oedges.second)) {
			if (target(e, graph) == a) {
				python::dict d;
				d.set("macro_name", graph[e].macro_name);
				d.set("parser_node", graph[e].parser_node);
				l.append(std::move(d));
			}
		}
		targets.set(graph[a].name, std::move(l));
	}

	return targets;
}

template <typename R>
auto make_python_object(graph_t const& graph, std::vector<R> const& roots) {
	auto list = python::list{};

	for (auto&& r : roots) {
		auto l = python::list{};
		l.append(std::get<0>(r));
		l.append(graph[std::get<1>(r)].name);
		l.append(std::get<2>(r));
		l.append(std::get<3>(r));
		list.append(std::move(l));
	}

	return list;
}
	
/**
 * Creates a Python Object for a graph vertex.
 */
auto make_python_object(graph_t const& graph, vertex_descriptor_t const& vertex) {
  auto obj = dict{};

  python::list tlv_nodes;

  for (auto&& t : graph[vertex].tlv_nodes)
  {
	  python::dict tlv;
	  tlv.set("name", t.name);
	  tlv.set("string_name", t.string_name);
	  tlv.set("metadata", t.metadata);
	  tlv.set("handler", t.handler);
	  tlv.set("type", t.type);
	  tlv.set("unknown_overlay_ret", t.unknown_overlay_ret);
	  tlv.set("wildcard_node", t.wildcard_node);
	  {
		  python::list overlay_nodes;
		  for (auto&& overlay : t.tlv_nodes) {
			  std::cout << "overlay is not empty, adding " <<
			  overlay.name << std::endl;
			  python::dict tlv_overlay;
			  tlv_overlay.set("name", overlay.name);
			  tlv_overlay.set("string_name", overlay.string_name);
			  tlv_overlay.set("metadata", overlay.metadata);
			  tlv_overlay.set("handler", overlay.handler);
			  tlv_overlay.set("type", overlay.type);
			  tlv_overlay.set("unknown_overlay_ret",
					  overlay.unknown_overlay_ret);
			  tlv_overlay.set("wildcard_node",
					  overlay.wildcard_node);
			  overlay_nodes.append(std::move(tlv_overlay));
		  }
		  tlv.set("overlay_nodes", std::move(overlay_nodes));
	  }
	  tlv_nodes.append(std::move(tlv));
  }
  
  python::list flag_fields_nodes;

  for (auto&& f : graph[vertex].flag_fields_nodes)
  {
	  python::dict flag;
	  flag.set("name", f.name);
	  flag.set("string_name", f.string_name);
	  flag.set("metadata", f.metadata);
	  flag.set("handler", f.handler);
	  flag.set("index", f.index);
	  flag_fields_nodes.append(std::move(flag));
  }

  auto& v = graph[vertex];
  obj.set("name", v.name);
  obj.set("parser_node", v.parser_node);
  obj.set("metadata", v.metadata);
  obj.set("handler", v.handler);
  obj.set("table", v.table);
  obj.set("tlv_table", v.table);
  obj.set("flag_fields_table", v.flag_fields_table);
  obj.set("unknown_proto_ret", v.unknown_proto_ret);
  obj.set("wildcard_proto_node", v.wildcard_proto_node);
  obj.set("tlv_nodes", std::move(tlv_nodes));
  obj.set("flag_fields_nodes", std::move(flag_fields_nodes));
  obj.set("out_edges", make_edge_list(graph, vertex));

  return obj;
}

/**
 * Creates a Python Object for a graph.
 *
 * Object is represented as a dictionary of vertex names to their data and
 * edges. For a single vertex, its edges are the names of the adjacent
 * vertices.
 */
auto make_python_object(graph_t const& graph) {
  auto obj = dict{};

  for (auto&& v_descriptor: boost::make_iterator_range(vertices(graph))) {
    auto& v = graph[v_descriptor];

    obj.set(v.name, make_python_object(graph, v_descriptor));
  }

  return obj;
}

struct module {
  auto get_function(std::string const& name) const {
    return make_python_object(ensure_not_null(
      PyObject_GetAttrString(py_module.get(), name.c_str()),
      std::string{"Failed to get '"} + name + "' from module"
    ));
  }

  auto get() const {
    return py_module.get();
  }

  python_object_t py_module;
};

auto import(std::string const& name) {
  return module{make_python_object(ensure_not_null(
    PyImport_ImportModule("template_gen"),
    "Failed to import module 'template_gen'"
  ))};
}

template <typename ...T>
auto call_function(python_object_t const& function, T... raw_args) {
  auto args = tuple(std::forward<T>(raw_args)...);
  auto call_result = PyObject_CallObject(function.get(), args.get());
  return ensure_not_null(call_result, "Failed to call function");
}

auto decode_locale(char const* str, size_t* size) {
  static auto ptr = [](auto* p) { PyMem_RawFree(p); };
  return std::unique_ptr<wchar_t[], decltype(ptr)>(
    Py_DecodeLocale(str, size),
    ptr
  );
}

struct error_checker {
  ~error_checker() {
    if (PyErr_Occurred()) {
      PyErr_Print();
    }
  }
};

void show_py_exception() {
  if (PyErr_Occurred()) {
    PyErr_Print();
  }
}

int generate_root_parser_c(std::string filename,
						   std::string output,
						   graph_t graph,
						   std::vector<root_t> roots)
{
	{
		auto ptr = [](auto* p) { PyMem_RawFree(p); };
		auto program_name = decode_locale("main.py", NULL);
		auto template_str = std::string(user_xdp_common_template_str) + std::string(c_def_template_str);

		Py_SetProgramName(program_name.get());
		Py_Initialize();

		auto checker = error_checker{};

		PyRun_SimpleString(pyratempsrc);
		PyRun_SimpleString(template_gen);

		auto generate_parser_entry_function = make_python_object(
        ensure_not_null(
           PyObject_GetAttrString(PyImport_AddModule("__main__"), "generate_parser_function"),
           std::string{"Failed to get 'generate_parser_function'"}
          ));

		{
			auto py_graph = make_python_object(graph);
			auto py_roots = make_python_object(graph, roots);

			call_function(
						  generate_parser_entry_function,
						  filename,
						  output,
						  py_graph.get(),
						  py_roots.get(),
						  template_str.c_str()
						  );
		}
	}

	if (Py_FinalizeEx() < 0) {
		std::cerr << "Error running generation template" << std::endl;
		return 120;
	}

	return 0;
}

int generate_root_parser_xdp_c(std::string filename,
							   std::string output,
							   graph_t graph,
							   std::vector<root_t> roots)
{
	{
		auto ptr = [](auto* p) { PyMem_RawFree(p); };
		auto program_name = decode_locale("main.py", NULL);
		auto template_str = std::string(user_xdp_common_template_str) + std::string(xdp_def_template_str);

		Py_SetProgramName(program_name.get());
		Py_Initialize();

		auto checker = error_checker{};

		PyRun_SimpleString(pyratempsrc);
		PyRun_SimpleString(template_gen);

		auto generate_parser_entry_function = make_python_object(
        ensure_not_null(
           PyObject_GetAttrString(PyImport_AddModule("__main__"), "generate_parser_function"),
           std::string{"Failed to get 'generate_parser_function'"}
          ));

		{
			auto py_graph = make_python_object(graph);
			auto py_roots = make_python_object(graph, roots);

			call_function(
						  generate_parser_entry_function,
						  filename,
						  output,
						  py_graph.get(),
						  py_roots.get(),
						  template_str.c_str()
						  );
		}
	}

	if (Py_FinalizeEx() < 0) {
		std::cerr << "Error running generation template" << std::endl;
		return 120;
	}

	return 0;
}

int generate_root_parser_kmod_c(std::string filename,
							   std::string output,
							   graph_t graph,
							   std::vector<root_t> roots)
{
	{
		auto ptr = [](auto *p) { PyMem_RawFree(p); };
		auto program_name = decode_locale("main.py", NULL);
		auto template_str = std::string(user_xdp_common_template_str) + std::string(kmod_def_template_str);

		Py_SetProgramName(program_name.get());
		Py_Initialize();

		auto checker = error_checker{};

		PyRun_SimpleString(pyratempsrc);
		PyRun_SimpleString(template_gen);

		auto generate_parser_entry_function = make_python_object(
				ensure_not_null(
			PyObject_GetAttrString(PyImport_AddModule("__main__"),
					       "generate_parser_function"),
			std::string{"Failed to get 'generate_parser_function'"}
		));

		{
			auto py_graph = make_python_object(graph);
			auto py_roots = make_python_object(graph, roots);

			call_function(
						  generate_parser_entry_function,
						  filename,
						  output,
						  py_graph.get(),
						  py_roots.get(),
						  template_str.c_str()
						  );
		}
	}

	if (Py_FinalizeEx() < 0) {
		std::cerr << "Error running generation template" << std::endl;
		return 120;
	}

	return 0;
}

}

#endif
