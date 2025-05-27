# A Garbled Circuits Engine build from scratch

There exist many GC libraries out there, written mostly in C or Rust, with various security guarantees, circuit optimisations, and levels of development activity.

This library is supposed to be a back-to-the-roots attempt of building a library in python with secure components only.


> This README will, in the near future, be extended heavily with a proper documentation

---

**Currently**, the project *gc_scratch* is:

- written in python
- supports semi-honest and malicious security (with inefficient cut&choose)
- does not include any circuit optimisations (such as Free XOR)
- uses native oblivious transfer (inefficient and also susceptible to further attacks)
- requires you to explicitly define the circuit (no E2E compiler)


In the **future**, this project will be

- maliciously secure, where the user can choose between cut-and-choose, and authenticated garbling
- dynamically assemble circuits (very first implementation of GRAM to my knowledgue)
- include input validation
- includes an interface for an adequate code-to-circuit compiler


---

### How to use

1. In one console, run `python garbler.py`
2. In another console run `python evaluator.py`



