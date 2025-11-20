use super::group_elements::GroupElement;
use super::scalars::{ScalarCanBeZero, ScalarNonZero};

impl<'b> std::ops::Add<&'b ScalarCanBeZero> for &ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn add(self, rhs: &'b ScalarCanBeZero) -> Self::Output {
        ScalarCanBeZero(self.0 + rhs.0)
    }
}

impl<'b> std::ops::Add<&'b ScalarCanBeZero> for ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn add(mut self, rhs: &'b ScalarCanBeZero) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl std::ops::Add<ScalarCanBeZero> for &ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn add(self, mut rhs: ScalarCanBeZero) -> Self::Output {
        rhs.0 += self.0;
        rhs
    }
}

impl std::ops::Add<ScalarCanBeZero> for ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn add(mut self, rhs: ScalarCanBeZero) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl<'b> std::ops::Sub<&'b ScalarCanBeZero> for &ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn sub(self, rhs: &'b ScalarCanBeZero) -> Self::Output {
        ScalarCanBeZero(self.0 - rhs.0)
    }
}

impl<'b> std::ops::Sub<&'b ScalarCanBeZero> for ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn sub(mut self, rhs: &'b ScalarCanBeZero) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl std::ops::Sub<ScalarCanBeZero> for &ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn sub(self, rhs: ScalarCanBeZero) -> Self::Output {
        ScalarCanBeZero(self.0 - rhs.0)
    }
}

impl std::ops::Sub<ScalarCanBeZero> for ScalarCanBeZero {
    type Output = ScalarCanBeZero;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl<'b> std::ops::Mul<&'b ScalarNonZero> for &ScalarNonZero {
    type Output = ScalarNonZero;

    fn mul(self, rhs: &'b ScalarNonZero) -> Self::Output {
        ScalarNonZero(self.0 * rhs.0)
    }
}

impl<'b> std::ops::Mul<&'b ScalarNonZero> for ScalarNonZero {
    type Output = ScalarNonZero;

    fn mul(mut self, rhs: &'b ScalarNonZero) -> Self::Output {
        self.0 *= rhs.0;
        self
    }
}

impl std::ops::Mul<ScalarNonZero> for &ScalarNonZero {
    type Output = ScalarNonZero;

    fn mul(self, mut rhs: ScalarNonZero) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}

impl std::ops::Mul<ScalarNonZero> for ScalarNonZero {
    type Output = ScalarNonZero;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self.0 *= rhs.0;
        self
    }
}

impl<'b> std::ops::Add<&'b GroupElement> for &GroupElement {
    type Output = GroupElement;

    fn add(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 + rhs.0)
    }
}

impl<'b> std::ops::Add<&'b GroupElement> for GroupElement {
    type Output = GroupElement;

    fn add(mut self, rhs: &'b GroupElement) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl std::ops::Add<GroupElement> for &GroupElement {
    type Output = GroupElement;

    fn add(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 += self.0;
        rhs
    }
}

impl std::ops::Add<GroupElement> for GroupElement {
    type Output = GroupElement;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl<'b> std::ops::Sub<&'b GroupElement> for &GroupElement {
    type Output = GroupElement;

    fn sub(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 - rhs.0)
    }
}

impl<'b> std::ops::Sub<&'b GroupElement> for GroupElement {
    type Output = GroupElement;

    fn sub(mut self, rhs: &'b GroupElement) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl std::ops::Sub<GroupElement> for &GroupElement {
    type Output = GroupElement;

    fn sub(self, rhs: GroupElement) -> Self::Output {
        GroupElement(self.0 - rhs.0)
    }
}

impl std::ops::Sub<GroupElement> for GroupElement {
    type Output = GroupElement;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl<'b> std::ops::Mul<&'b GroupElement> for &ScalarNonZero {
    type Output = GroupElement;

    fn mul(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl<'b> std::ops::Mul<&'b GroupElement> for ScalarNonZero {
    type Output = GroupElement;

    fn mul(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl std::ops::Mul<GroupElement> for &ScalarNonZero {
    type Output = GroupElement;

    fn mul(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}

impl std::ops::Mul<GroupElement> for ScalarNonZero {
    type Output = GroupElement;

    fn mul(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}

impl<'b> std::ops::Mul<&'b GroupElement> for &ScalarCanBeZero {
    type Output = GroupElement;

    fn mul(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl<'b> std::ops::Mul<&'b GroupElement> for ScalarCanBeZero {
    type Output = GroupElement;

    fn mul(self, rhs: &'b GroupElement) -> Self::Output {
        GroupElement(self.0 * rhs.0)
    }
}

impl std::ops::Mul<GroupElement> for &ScalarCanBeZero {
    type Output = GroupElement;

    fn mul(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}

impl std::ops::Mul<GroupElement> for ScalarCanBeZero {
    type Output = GroupElement;

    fn mul(self, mut rhs: GroupElement) -> Self::Output {
        rhs.0 *= self.0;
        rhs
    }
}
