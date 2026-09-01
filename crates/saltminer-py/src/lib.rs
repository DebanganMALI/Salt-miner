use pyo3::prelude::*;

#[pyfunction]
fn identify(input: &str) -> Vec<(String, String, String)> {
    saltminer_core::identify(input)
        .into_iter()
        .map(|c| {
            (
                c.algorithm,
                format!("{:?}", c.confidence).to_lowercase(),
                c.reason,
            )
        })
        .collect()
}

#[pyfunction]
fn audit(input: &str) -> Option<(String, String, String)> {
    saltminer_core::audit(input).map(|r| (r.algorithm, format!("{:?}", r.verdict), r.detail))
}

#[pymodule]
fn saltminer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(identify, m)?)?;
    m.add_function(wrap_pyfunction!(audit, m)?)?;
    Ok(())
}
