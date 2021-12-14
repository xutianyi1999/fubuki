pub mod persistence;
pub mod net;

pub enum Either<L, R> {
    Right(R),
    Left(L),
}