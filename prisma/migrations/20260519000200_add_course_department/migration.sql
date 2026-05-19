ALTER TABLE "Course" ADD COLUMN "departmentId" TEXT;

ALTER TABLE "Course"
ADD CONSTRAINT "Course_departmentId_fkey"
FOREIGN KEY ("departmentId") REFERENCES "Department"("id")
ON DELETE SET NULL ON UPDATE CASCADE;
